"""
Tarvia SOC - L3 investigation: attack-chain reconstruction (deterministic, evidence-based).

For each selected incident (default: status = escalate_n2):
  1. Seed pivots from its alerts (users, hosts, external IPs, domains, URLs, hashes, message/session ids,
     customers, cloud identities/keys) and from structured evidence fields.
  2. Search dim_log around the incident (and the whole dataset for attacker artefacts), keep only events with
     security meaning, and expand pivots (lateral movement, accounts created/used, attacker IPs, payloads).
  3. Classify every event into MITRE ATT&CK / ATLAS, compress repetitions (beaconing, stuffing waves) into steps.
  4. Write fact_attack_step (alert / hidden_log / context) and the incident report fields; export
     reports/<incident_id>.json following informe_incidente.schema.json.
Attacker-controllable text (subjects, prompts, command lines) is never copied into descriptions verbatim
beyond the executable name / technique; it is data, not instructions.

Usage: python l3_reconstruct.py --db tarvia_soc.sqlite [--incident INC-...] [--status escalate_n2] [--reports DIR]
"""

import argparse
import collections
import ipaddress
import json
import pathlib
import re
import sqlite3
from datetime import datetime, timedelta, timezone

PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")
BENIGN_PROCS = {
    "msedge.exe",
    "excel.exe",
    "winword.exe",
    "acrobat.exe",
    "onedrive.exe",
    "svchost.exe",
    "msmpeng.exe",
    "outlook.exe",
    "chrome.exe",
    "ccmexec.exe",
    "ms-teams.exe",
    "sapgui.exe",
    "services.exe",
    "saplogon.exe",
}
CORPORATE_EGRESS = {"198.18.200.10"}  # Tarvia exit IP (Orange, Barcelona/Madrid): never an attacker pivot
ADMIN_PORTS = {
    "445": "T1021.002",
    "3389": "T1021.001",
    "5985": "T1021.006",
    "5986": "T1021.006",
    "22": "T1021.004",
    "135": "T1021.003",
}
LOOKAROUND = timedelta(hours=72)
MAX_EVENTS_PER_QUERY = 6000
CAP = {"users": 12, "hosts": 12, "ips": 40, "domains": 20, "hashes": 20}
CLOUD_STORAGE = ("mega.nz", "wetransfer", "dropbox", "drive.google", "anonfiles", "transfer.sh", "pastebin")


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def iso(d):
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def nuser(v):
    if not v or not isinstance(v, str):
        return None
    v = v.strip().lower().split("\\")[-1].split("@")[0]
    return v or None


def is_ext_ip(v):
    try:
        ipaddress.ip_address(v)
    except Exception:
        return False
    return not PRIVATE.match(v) and v not in CORPORATE_EGRESS


class Ctx:
    def __init__(s, con):
        s.con = con
        s.mitre = {
            r[0]: (r[1], r[2], r[3])
            for r in con.execute("SELECT technique_id, technique, tactic, kill_chain_order FROM dim_mitre")
        }
        s.asset_by_ip = {
            r[0]: r[1] for r in con.execute("SELECT ip, hostname FROM dim_vulnerability WHERE ip IS NOT NULL")
        }
        s.assets = {r["hostname"]: r for r in con.execute("SELECT * FROM dim_vulnerability")}
        s.users = {r["user_key"]: r for r in con.execute("SELECT * FROM dim_user")}
        s.geo = {
            r["context_key"]: r
            for r in con.execute("SELECT * FROM dim_context WHERE context_type IN ('ip','domain','url','sha256')")
        }
        s.domain_hosts = {
            r[0]: r[1]
            for r in con.execute(
                "SELECT dst, COUNT(DISTINCT hostname) FROM dim_log WHERE source IN ('proxy','dns') GROUP BY dst"
            )
        }
        from zoneinfo import ZoneInfo

        mad = ZoneInfo("Europe/Madrid")

        def expand(tok):
            m = re.match(r"^(.*?)(\d+)\.\.(\d+)$", tok)
            return (
                [f"{m.group(1)}{i:0{len(m.group(2))}d}" for i in range(int(m.group(2)), int(m.group(3)) + 1)]
                if m
                else [tok]
            )

        s.changes = []
        for c in con.execute("SELECT * FROM dim_context WHERE context_type='change'"):
            text = f'{c["change_detail"]} {c["change_scope"]}'
            toks = {x for t in re.findall(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*\d+(?:\.\.\d+)?\b", text) for x in expand(t)}
            toks |= set(re.findall(r"\b(?:svc_[a-z0-9_]+|ext\.[a-z0-9_.]+)\b", text))
            conv = lambda v: datetime.strptime(v, "%Y-%m-%d %H:%M").replace(tzinfo=mad).astimezone(timezone.utc)
            s.changes.append(
                dict(
                    id=c["context_key"],
                    title=c["change_title"],
                    toks=toks,
                    start=conv(c["change_start"]),
                    end=conv(c["change_end"]),
                )
            )
        s.hash_hosts = {
            r[0]: r[1]
            for r in con.execute(
                "SELECT sha256, COUNT(DISTINCT hostname) FROM dim_log WHERE sha256 IS NOT NULL GROUP BY sha256"
            )
        }
        s.user_countries = collections.defaultdict(collections.Counter)
        for u, c, n in con.execute(
            "SELECT user_key, json_extract(detail,'$.country'), COUNT(*) FROM dim_log "
            "WHERE source IN ('idp_signins','vpn') AND result IN ('success','connect','approved') GROUP BY 1,2"
        ):
            s.user_countries[u][c] = n

    def tech(s, tid):
        """validate against dim_mitre (falls back to parent technique)."""
        if not tid:
            return None
        if tid in s.mitre:
            return tid
        p = tid.split(".")[0]
        return p if p in s.mitre else None

    def malicious(s, v):
        r = s.geo.get(v)
        return bool(r and (r["reputation"] == "malicious" or r["sandbox_verdict"] == "malicious"))

    def risky_ip(s, v):
        r = s.geo.get(v)
        return bool(
            r
            and (
                r["is_tor"]
                or r["is_vpn_provider"]
                or r["is_residential_proxy"]
                or r["reputation"] in ("malicious", "suspicious")
            )
        )

    def attacker_domain(s, v):
        """domain usable as a global pivot: known-bad or rare (<= 3 hosts); popular dual-use services are not."""
        return s.malicious(v) or s.domain_hosts.get(v, 0) <= 3

    def rare_hash(s, h):
        return s.malicious(h) or s.hash_hosts.get(h, 0) <= 3


# ------------------------------------------------------------------ classification
def classify(ev, d, P, X):
    """return (technique_id, short description) or None if the event has no security meaning."""
    src, act, res, dst = ev["source"], (ev["action"] or ""), (ev["result"] or ""), (ev["dst"] or "")
    host, user, sip = ev["hostname"], ev["user_key"], ev["src_ip"]
    gdom = (
        {x for x in P["domains"] if X.attacker_domain(x)}
        if host not in P["hosts"] and user not in P["users"]
        else P["domains"]
    )
    ioc = (
        sip in P["ips"]
        or any(x and x in dst for x in gdom | P["ips"] | P["urls"])
        or (ev["sha256"] and ev["sha256"] in P["hashes"])
        or (ev["ref_id"] and ev["ref_id"] in P["refs"])
    )
    if src == "email":
        atts = d.get("attachments") or []
        bad_att = any(
            isinstance(a, dict) and (a.get("sha256") in P["hashes"] or X.malicious(a.get("sha256"))) for a in atts
        )
        bad_url = any(
            u in P["urls"] or X.malicious(u) or any(dm in u for dm in P["domains"]) for u in (d.get("urls") or [])
        )
        if d.get("direction") == "inbound" and (
            ioc or bad_att or bad_url or d.get("verdict") in ("phishing", "malicious")
        ):
            return (
                "T1566.001" if atts else "T1566.002",
                f'Phishing email delivered to {", ".join(d.get("recipients") or [])[:80]} from {d.get("sender")}'
                + (f' with attachment {atts[0].get("name")}' if atts and isinstance(atts[0], dict) else ""),
            )
        if d.get("direction") in ("internal", "outbound") and nuser(d.get("sender")) in P["users"] and ioc:
            rc = d.get("recipients") or []
            if rc and all(str(r).lower().endswith("@tarvia.example") for r in rc):
                return (
                    "T1534",
                    f'Internal email sent from compromised mailbox {d.get("sender")} to {", ".join(rc)[:60]}',
                )
            return (
                "T1048.003",
                f'Email with data sent from {d.get("sender")} to external address {", ".join(rc)[:60]}',
            )
        return None
    if src == "email_clicks":
        if ioc or "phish" in str(d.get("verdict_at_click", "")):
            return ("T1204.001", f'{d.get("user")} clicked {dst[:80]} (verdict at click: {d.get("verdict_at_click")})')
        return None
    if src == "edr_events":
        p = dst.lower()
        cl = (d.get("command_line") or "").lower()
        par = (d.get("parent_name") or "").lower()
        det = d.get("details") or {}
        if (
            act == "detection"
            and not ioc
            and str(det.get("action", "")).lower() in ("quarantined", "deleted", "blocked")
        ):
            return None  # commodity malware already stopped by the AV, not part of this intrusion
        if act == "detection":
            return ("T1204.002", f'EDR detection on {host}: {det.get("detection") or p} (action {det.get("action")})')
        if act == "registry_set" and "run" in json.dumps(d).lower():
            return ("T1547.001", f"Run-key persistence set by {p} on {host}")
        if act == "file_create":
            return ("T1105", f"Payload written to disk by {p} on {host}")
        if act == "process_access" and ("lsass" in json.dumps(d).lower() or "minidump" in cl):
            return ("T1003.001", f"LSASS memory access by {p} on {host}")
        if act == "service_install":
            return ("T1569.002", f"Service installed on {host} ({p})")
        if act == "agent_status":
            return ("T1562.001", f"EDR agent state change on {host}: {res}")
        if act == "network_connect" and ioc:
            return ("T1071.001", f"{p} on {host} connected to attacker infrastructure")
        rules = [
            ("comsvcs", "T1003.001", "LSASS dump via comsvcs.dll"),
            ("vssadmin", "T1490", "Shadow copies deleted"),
            ("wbadmin", "T1490", "Backup catalog deleted"),
            ("sc.exe", "T1562.001", "Security service stopped"),
            ("wscript", "T1059.007", "Script executed with wscript"),
            ("cscript", "T1059.005", "Script executed with cscript"),
            ("mshta", "T1218.005", "mshta execution"),
            ("msiexec", "T1218.007", "msiexec installing remote package"),
            ("rundll32", "T1218.011", "rundll32 executing DLL"),
            ("regsvr32", "T1218.010", "regsvr32 proxy execution"),
            ("whoami", "T1033", "Account discovery (whoami)"),
            ("nltest", "T1482", "Domain trust discovery (nltest)"),
            ("adf.exe", "T1087.002", "AD enumeration (AdFind)"),
            ("net.exe", "T1087.002", "Domain account/group discovery (net)"),
            ("psexe", "T1569.002", "PsExec service execution"),
            ("anydesk", "T1219", "Remote access tool"),
            ("7zg", "T1560.001", "Data archived with 7-Zip"),
            ("sqlcmd", "T1213", "Database queried with sqlcmd"),
            ("crontab", "T1053.003", "Cron persistence"),
            ("kswapd0", "T1496", "Cryptominer masquerading as kswapd0"),
            ("schtasks", "T1053.005", "Scheduled task"),
            ("possvc", "T1005", "Process on POS terminal"),
        ]
        if p in BENIGN_PROCS and not ioc:
            return None
        if p == "powershell.exe":
            if "ccmexec" in par and not ioc:
                return None
            return ("T1059.001", f"PowerShell on {host} (parent {par})")
        for k, t, txt in rules:
            if k in p or (k in cl and k not in ("net.exe",)):
                return (t, f"{txt} on {host} as {user}")
        if ev["sha256"] and (ev["sha256"] in P["hashes"] or X.malicious(ev["sha256"])):
            return ("T1204.002", f"Known-bad binary {p} executed on {host}")
        if host in P["hosts"] and (not d.get("signer") or d.get("signer") in ("", "N/A", "sin firma")):
            return ("T1036", f"Unsigned binary {p} executed on {host}")
        return None
    if src in ("proxy", "dns"):
        if ioc or X.malicious(dst):
            return ("T1071.004" if src == "dns" else "T1071.001", f"{host or sip} contacted attacker domain {dst}")
        bout = d.get("bytes_out")
        if src == "proxy" and host in P["hosts"] and bout and str(bout).isdigit() and int(bout) > 20_000_000:
            return (
                "T1567.002" if any(c in dst for c in CLOUD_STORAGE) else "T1048",
                f"{host} uploaded {int(bout)//1_000_000} MB to {dst}",
            )
        return None
    if src == "firewall":
        dip, dport = (dst.split(":") + [""])[:2]
        if dip in P["ips"] or X.malicious(dip):
            return ("T1071.001", f"{sip} -> {dip}:{dport} (attacker infrastructure, {act})")
        if PRIVATE.match(dip) and dport in ADMIN_PORTS and X.asset_by_ip.get(sip) in P["hosts"]:
            return (ADMIN_PORTS[dport], f"{X.asset_by_ip.get(sip)} -> {X.asset_by_ip.get(dip, dip)}:{dport} ({act})")
        return None
    if src == "idp_signins":
        if user not in P["users"] and sip not in P["ips"]:
            return None
        r = res.lower()
        mfa = str(d.get("mfa_result", "")).lower()
        if mfa in ("denied", "timeout"):
            return ("T1621", f"MFA push {mfa} for {user} from {sip}")
        new_country = d.get("country") and X.user_countries[user][d.get("country")] <= 2
        noncompliant = d.get("device_compliant") in (False, 0)
        if r == "success" and (
            sip in P["ips"]
            or X.risky_ip(sip)
            or (noncompliant and (new_country or d.get("risk_level") in ("medium", "high")))
        ):
            return (
                "T1078.004",
                f'Successful sign-in of {user} to {d.get("app")} from {sip} ({d.get("country")}, {d.get("asn")})',
            )
        if r != "success" and sip in P["ips"]:
            return ("T1110", f"Failed sign-in for {user} from attacker IP {sip}")
        return None
    if src == "idp_audit":
        op = act
        m = {
            "New-InboxRule": ("T1564.008", "Inbox rule created"),
            "Consent to application": ("T1528", "OAuth consent granted"),
            "Add-MfaMethod": ("T1098.005", "MFA method registered"),
            "MailItemsAccessed": ("T1114.002", "Mailbox items accessed"),
            "FileDownloaded": ("T1530", "Files downloaded from SaaS storage"),
            "Set-MailboxAutoReply": ("T1098", "Mailbox auto-reply changed"),
            "Change password": ("T1098", "Password changed"),
        }.get(op)
        high_risk = op in ("New-InboxRule", "Consent to application", "Add-MfaMethod")
        if m and (sip in P["ips"] or X.risky_ip(sip) or (user in P["users"] and high_risk and sip and is_ext_ip(sip))):
            return (m[0], f"{m[1]} by {user} from {sip}")
        return None
    if src == "ad_events":
        code = res
        m = {
            "4720": ("T1136.002", "Domain account created"),
            "4728": ("T1098.007", "Member added to privileged group"),
            "4732": ("T1098.007", "Member added to local group"),
            "4756": ("T1098.007", "Member added to universal group"),
            "4769": ("T1558.003", "Kerberos service ticket requested"),
            "4625": ("T1110", "Failed logon"),
        }.get(code)
        if m and (user in P["users"] or host in P["hosts"] or nuser(dst) in P["users"]):
            return (m[0], f"{m[1]}: {dst} by {user} on {host}")
        return None
    if src == "cloudtrail":
        ident = user
        if ident not in P["users"] and sip not in P["ips"] and not (ev["ref_id"] and ev["ref_id"] in P["refs"]):
            return None
        if not (
            sip in P["ips"] or (sip and is_ext_ip(sip)) or act in ("CreateUser", "CreateAccessKey", "AttachUserPolicy")
        ):
            return None
        m = {
            "GetCallerIdentity": "T1087.004",
            "ListUsers": "T1087.004",
            "ListBuckets": "T1619",
            "ListObjects": "T1619",
            "DescribeInstances": "T1580",
            "CreateUser": "T1136.003",
            "CreateAccessKey": "T1098.001",
            "AttachUserPolicy": "T1098.003",
            "GetObject": "T1530",
            "PutBucketPolicy": "T1530",
            "GetBucketPolicy": "T1619",
            "ConsoleLogin": "T1078.004",
        }
        return (
            m.get(act, "T1078.004"),
            f"AWS {act} by {ident} from {sip}" + (f" ({res})" if res and res != "success" else ""),
        )
    if src == "dlp":
        if user in P["users"] or host in P["hosts"]:
            return (
                "T1567.002" if any(c in dst for c in CLOUD_STORAGE) else "T1048",
                f'DLP: {d.get("file_name")} -> {dst} ({d.get("action")}, policy {d.get("policy")})',
            )
        return None
    if src == "sql_audit":
        try:
            rows = int(res)
        except Exception:
            rows = 0
        if (user in P["users"] or host in P["hosts"]) and rows >= 1000:
            return ("T1213", f"{rows} rows read from {dst} by {user} on {host}")
        return None
    if src == "vpn":
        if user in P["users"] and (sip in P["ips"] or X.risky_ip(sip)):
            return ("T1133", f"VPN {act} of {user} from {sip} ({d.get('country')})")
        return None
    if src == "ecom_auth":
        if sip in P["ips"] or ev["customer_id"] in P["customers"]:
            return (
                ("T1078", f"Customer login success {ev['customer_id']} from {sip} (fp {d.get('device_fp')})")
                if res == "success"
                else ("T1110.004", f"Credential stuffing attempt from {sip}")
            )
        return None
    if src == "ecom_account":
        if ev["customer_id"] in P["customers"] or sip in P["ips"]:
            if act == "giftcard_purchase":
                return ("T1657", f"Gift card bought from account {ev['customer_id']} ({d.get('amount')} EUR)")
            if act == "email_change":
                return ("T1098", f"Account email changed on {ev['customer_id']}")
            if act == "address_change":
                return ("T1098", f"Delivery address changed on {ev['customer_id']}")
            return None
        return None
    if src == "ai_gateway":
        g = d.get("guardrail") or {}
        if (sip in P["ips"] or ev["ref_id"] in P["refs"] or ev["customer_id"] in P["customers"]) and g.get("triggered"):
            return (
                "AML.T0057"
                if "datos" in str(g.get("category", "")).lower() or "other" in str(g.get("category", "")).lower()
                else "AML.T0051",
                f"AI assistant guardrail '{g.get('category')}' ({g.get('action')}) in session {ev['ref_id']}",
            )
        return None
    if src == "waf":
        if sip in P["ips"]:
            return ("T1190", f"Web attack from {sip}: rule {res} ({act})")
        return None
    if src == "cicd_builds":
        det = d.get("details") or {}
        secrets = [e for e in (det.get("env_read") or []) if re.search(r"AWS|TOKEN|SECRET|KEY|PASSW|DSN", str(e), re.I)]
        if secrets and det.get("network"):
            return (
                "T1195.001",
                f'Build step {act} in {dst} read {", ".join(secrets)} and sent data out ({str(det.get("network"))[:60]})',
            )
        return None
    return None


# ------------------------------------------------------------------ investigation
def investigate(con, X, iid):
    q = lambda s, *p: con.execute(s, p).fetchall()
    inc = q("SELECT * FROM fact_incident WHERE incident_id=?", iid)[0]
    alerts = q(
        """SELECT a.* FROM bridge_alert_incident b JOIN fact_alert a USING(alert_id)
                  WHERE b.incident_id=? ORDER BY a.created_at""",
        iid,
    )
    alert_ids = [a["alert_id"] for a in alerts]
    alert_events = {
        r[0]: r[1]
        for r in q(
            f"SELECT event_id, alert_id FROM bridge_alert_event WHERE alert_id IN ({','.join('?'*len(alert_ids))})",
            *alert_ids,
        )
    }
    P = {k: set() for k in ("users", "hosts", "ips", "domains", "urls", "hashes", "refs", "customers")}
    for r in q(f"SELECT * FROM bridge_alert_entity WHERE alert_id IN ({','.join('?'*len(alert_ids))})", *alert_ids):
        t, v = r["entity_type"], r["entity_value"]
        if t == "user" and r["user_key"]:
            P["users"].add(r["user_key"])
        elif t == "user":
            P["users"].add(nuser(v))
        elif t == "host":
            P["hosts"].add(v)
        elif t == "ip" and is_ext_ip(v):
            P["ips"].add(v)
        elif t == "domain":
            P["domains"].add(v)
        elif t == "url":
            P["urls"].add(v)
        elif t == "file" and re.fullmatch(r"[0-9a-f]{64}", v):
            P["hashes"].add(v)
        elif t == "customer":
            P["customers"].add(v)
        elif t in ("cloud_identity",):
            P["users"].add(nuser(v))
        elif t in ("access_key", "ai_session"):
            P["refs"].add(v)
    for a in alerts:
        ev = json.loads(a["evidence"] or "{}")
        for k in ("message_id", "session_id"):
            if ev.get(k):
                P["refs"].add(str(ev[k]))
        for k in ("src_ip", "created_from_ip", "submitted_from_ip", "dst_ip"):
            if ev.get(k) and is_ext_ip(str(ev[k])):
                P["ips"].add(str(ev[k]))
        for k in ("account", "by"):
            if ev.get(k):
                P["users"].add(nuser(str(ev[k])))
        for k in ("src", "dst", "from_host"):
            if ev.get(k) in X.assets:
                P["hosts"].add(ev[k])
        for u in ev.get("cached_credentials_on_host") or []:
            P["users"].add(nuser(u))
        m = re.match(r"(\S+)", str(ev.get("member_added", "")))
        if m:
            P["users"].add(nuser(m.group(1)))
    P["users"].discard(None)
    P["users"] = {u for u in P["users"] if not u.startswith("(")}
    t0, t1 = ts(inc["first_seen"]) - LOOKAROUND, ts(inc["last_seen"]) + LOOKAROUND
    for a in alerts:
        ev = json.loads(a["evidence"] or "{}")
        for v in (ev.get("usual_sources") or []) + (
            ev.get("usual_src") or [] if isinstance(ev.get("usual_src"), list) else []
        ):
            ip = str(v).split()[0]
            if ip in X.asset_by_ip:
                P["hosts"].add(X.asset_by_ip[ip])
    normal = set()
    for ip in P["ips"]:
        n_users, n_before = con.execute(
            """SELECT COUNT(DISTINCT user_key),
               SUM(CASE WHEN timestamp < ? AND result IN ('success','approved') THEN 1 ELSE 0 END)
               FROM dim_log WHERE src_ip=? AND source IN ('idp_signins','vpn')""",
            (inc["first_seen"], ip),
        ).fetchone()
        if (n_users or 0) > 20 or (n_before or 0) >= 2:
            normal.add(ip)  # shared egress or the user's usual IP
    P["ips"] -= normal

    authorised = collections.Counter()

    def is_authorised(ev):
        t = ts(ev["timestamp"])
        for c in X.changes:
            if c["start"] <= t <= c["end"] and (
                (ev["hostname"] and ev["hostname"] in c["toks"]) or (ev["user_key"] and ev["user_key"] in c["toks"])
            ):
                return c["id"]
        return None

    found = {}

    def run(sql, params, scope_all=False):
        w = "" if scope_all else " AND timestamp BETWEEN ? AND ?"
        p = list(params) + ([] if scope_all else [iso(t0), iso(t1)])
        for ev in con.execute(sql + w + f" ORDER BY timestamp LIMIT {MAX_EVENTS_PER_QUERY}", p):
            if ev["event_id"] in found:
                continue
            d = json.loads(ev["detail"])
            c = classify(ev, d, P, X)
            if c and X.tech(c[0]) is not None or (c and c[0].startswith("AML")):
                if ev["event_id"] not in alert_events:
                    cid = is_authorised(ev)
                    if cid:
                        authorised[cid] += 1
                        continue
                found[ev["event_id"]] = (ev, d, X.tech(c[0]) or c[0], c[1])

    base = "SELECT * FROM dim_log WHERE "
    for rnd in range(3):
        before = {k: set(v) for k, v in P.items()}
        for u in sorted(P["users"])[: CAP["users"]]:
            run(base + "user_key=?", [u])
        for h in sorted(P["hosts"])[: CAP["hosts"]]:
            run(base + "hostname=?", [h])
        for ip in sorted(P["ips"])[: CAP["ips"]]:
            run(base + "src_ip=?", [ip], True)
            run(base + "dst LIKE ?", [ip + "%"], True)
        for dm in sorted(P["domains"])[: CAP["domains"]]:
            if X.attacker_domain(dm):
                run(base + "dst=?", [dm], True)
        for hs in sorted(P["hashes"])[: CAP["hashes"]]:
            if X.rare_hash(hs):
                run(base + "sha256=?", [hs], True)
        for rf in sorted(P["refs"]):
            run(base + "ref_id=?", [rf], True)
        for cu in sorted(P["customers"]):
            run(base + "customer_id=?", [cu])
        # pivot expansion from what was found
        for ev, d, tid, _ in found.values():
            s = ev["source"]
            if s == "firewall" and tid and tid.startswith("T1021"):
                h = X.asset_by_ip.get(ev["dst"].split(":")[0])
                if h and len(P["hosts"]) < CAP["hosts"] and d.get("action") in ("allow", "accept"):
                    P["hosts"].add(h)
            if s == "edr_events" and ev["hostname"] in P["hosts"]:
                u = ev["user_key"]
                if u and (u.startswith("adm.") or u.startswith("svc_")) and len(P["users"]) < CAP["users"]:
                    P["users"].add(u)
                quarantined = ev["source"] == "edr_events" and str(
                    (d.get("details") or {}).get("action", "")
                ).lower() in ("quarantined", "blocked", "deleted")
                if ev["sha256"] and not quarantined and X.rare_hash(ev["sha256"]) and len(P["hashes"]) < CAP["hashes"]:
                    P["hashes"].add(ev["sha256"])
            if (
                s == "edr_events"
                and ev["sha256"] in P["hashes"]
                and X.rare_hash(ev["sha256"])
                and ev["hostname"]
                and len(P["hosts"]) < CAP["hosts"]
            ):
                P["hosts"].add(ev["hostname"])
            if s == "ad_events":
                tgt = nuser(ev["dst"])
                if tgt and tid in ("T1136.002", "T1098.007"):
                    P["users"].add(tgt)
                if ev["hostname"] in X.assets:
                    P["hosts"].add(ev["hostname"])
            if s == "cloudtrail" and ev["src_ip"] in X.asset_by_ip and len(P["hosts"]) < CAP["hosts"]:
                P["hosts"].add(X.asset_by_ip[ev["src_ip"]])
            if (
                s in ("idp_signins", "cloudtrail", "vpn", "idp_audit")
                and tid
                and ev["src_ip"]
                and is_ext_ip(ev["src_ip"])
                and (X.risky_ip(ev["src_ip"]) or ev["src_ip"] in P["ips"] or s == "cloudtrail")
            ):
                P["ips"].add(ev["src_ip"])
            if s in ("proxy", "dns") and X.malicious(ev["dst"]) and len(P["domains"]) < CAP["domains"]:
                P["domains"].add(ev["dst"])
            if s == "ecom_auth" and ev["src_ip"] in P["ips"] and ev["result"] == "success" and ev["customer_id"]:
                P["customers"].add(ev["customer_id"])
        if all(P[k] == before[k] for k in P):
            break

    # ---------------- context steps (HR, vulnerabilities)
    ctx_steps = []
    for u in sorted(P["users"]):
        r = X.users.get(u)
        if r and r["hr_event"]:
            when = datetime.fromisoformat(r["hr_event_date"]).replace(tzinfo=timezone.utc)
            ctx_steps.append(
                (
                    when,
                    None,
                    None,
                    None,
                    u,
                    None,
                    "context",
                    f'HR context: {u} - {r["hr_event"]} (effective {r["hr_fecha_efectiva"]}): {r["hr_detalle"][:90]}',
                )
            )
    for cid, n in authorised.items():
        c = next(c for c in X.changes if c["id"] == cid)
        ctx_steps.append(
            (
                c["start"],
                None,
                None,
                None,
                None,
                None,
                "context",
                f'{n} event(s) on in-scope entities excluded: covered by approved change {cid} "{c["title"]}"',
            )
        )
    for h in sorted(P["hosts"]):
        a = X.assets.get(h)
        if a and a["open_vuln_count"]:
            ctx_steps.append(
                (
                    t0,
                    None,
                    None,
                    None,
                    None,
                    h,
                    "context",
                    f'Exposure: {h} has {a["open_vuln_count"]} open vulnerabilities ({a["cve_ids"][:90]})',
                )
            )

    # ---------------- compress into steps
    evs = sorted(found.values(), key=lambda x: (x[0]["timestamp"], x[0]["event_id"]))
    steps, cur = [], None
    for ev, d, tid, desc in evs:
        wave = tid in ("T1110", "T1110.004", "T1190", "T1071.001", "T1071.004") and not ev["hostname"]
        key = (
            ev["source"],
            tid,
            None if wave else (ev["hostname"] or ev["user_key"] or ev["customer_id"] or ev["src_ip"]),
            "" if wave and ev["source"] in ("ecom_auth", "waf", "firewall") else (ev["dst"] or "")[:40],
        )
        t = ts(ev["timestamp"])
        origin = "alert" if ev["event_id"] in alert_events else "hidden_log"
        if (
            cur
            and cur["key"] == key
            and t - cur["last"] <= timedelta(minutes=30)
            and (
                key[1] in ("T1071.001", "T1071.004", "T1110", "T1110.004", "T1190", "T1621", "T1213", "T1530")
                or origin == cur["origin"] == "hidden_log"
            )
        ):
            cur["n"] += 1
            cur["last"] = t
            if origin == "alert":
                cur["origin"] = "alert"
                cur["alert"] = cur["alert"] or alert_events.get(ev["event_id"])
            continue
        cur = dict(
            key=key, t=t, last=t, ev=ev, tid=tid, desc=desc, n=1, origin=origin, alert=alert_events.get(ev["event_id"])
        )
        steps.append(cur)
    # merge in alert-only evidence (alerts whose events were not classified) so no alert is lost
    covered = {s["alert"] for s in steps if s["alert"]}
    for a in alerts:
        if a["alert_id"] not in covered:
            steps.append(
                dict(
                    key=None,
                    t=ts(a["created_at"]),
                    last=ts(a["created_at"]),
                    ev=None,
                    tid=X.tech(a["technique_id"]) or a["technique_id"],
                    desc=f'Alert {a["rule_id"]}: {a["rule_name"]}',
                    n=1,
                    origin="alert",
                    alert=a["alert_id"],
                )
            )
    for c in ctx_steps:
        steps.append(
            dict(
                key=None,
                t=c[0],
                last=c[0],
                ev=None,
                tid=None,
                desc=c[7],
                n=1,
                origin="context",
                alert=None,
                user=c[4],
                host=c[5],
            )
        )
    steps.sort(
        key=lambda s: (
            s["t"],
            X.mitre.get(s["tid"], (None, None, None, 99))[2] or 99,
            s["ev"]["event_id"] if s["ev"] is not None else "~" + s["desc"],
        )
    )
    if len(steps) > 120:  # keep every alert / context step + first occurrence of each hidden technique per entity
        fixed = [s for s in steps if s["origin"] != "hidden_log"]
        seen, hid = set(), []
        for s in steps:
            if s["origin"] != "hidden_log":
                continue
            k = (s["tid"], s["key"][2] if s["key"] else None)
            if k not in seen:
                seen.add(k)
                hid.append(s)
        steps = sorted(fixed + hid[: max(0, 120 - len(fixed))], key=lambda s: s["t"])

    # ---------------- report fields
    tactics = [X.mitre[s["tid"]][1] for s in steps if s["tid"] in X.mitre and X.mitre[s["tid"]][1]]
    kco = max([X.mitre[s["tid"]][2] or 0 for s in steps if s["tid"] in X.mitre] or [0]) or None
    ia_cands = [s for s in steps if s["tid"] in X.mitre and X.mitre[s["tid"]][1] == "Initial Access"]
    ia = (
        next((s for s in ia_cands if s["tid"].startswith(("T1566", "T1190", "T1133", "T1195", "T1110"))), None)
        or next(iter(ia_cands), None)
        or next((s for s in steps if s["origin"] != "context"), steps[0])
    )
    iev = ia["ev"]
    pz = None
    if iev is not None and not (
        iev["user_key"] or iev["hostname"] or iev["customer_id"] or (json.loads(iev["detail"]).get("recipients"))
    ):
        first_victim = next(
            (
                s["ev"]
                for s in steps
                if s["ev"] is not None and (s["ev"]["customer_id"] or s["ev"]["user_key"] or s["ev"]["hostname"])
            ),
            None,
        )
        if first_victim is not None:
            pz = first_victim["customer_id"] or first_victim["user_key"] or first_victim["hostname"]
    if iev is not None and pz is None:
        d0 = json.loads(iev["detail"])
        rc = d0.get("recipients") or []
        pz = (nuser(rc[0]) if rc else None) or iev["user_key"] or iev["hostname"] or iev["customer_id"] or iev["src_ip"]
    pz = (
        pz
        or inc["primary_user_key"]
        or inc["primary_hostname"]
        or (sorted(P["customers"])[0] if P["customers"] else None)
        or (sorted(P["ips"])[0] if P["ips"] else "unknown")
    )
    hidden = [s for s in steps if s["origin"] == "hidden_log"]
    svc = sorted(
        {
            f'{X.assets[h]["business_service"]} ({X.assets[h]["service_criticidad"] or X.assets[h]["criticality"]})'
            for h in P["hosts"]
            if h in X.assets
        }
    )
    data_bits = []
    for a in alerts:
        ev = json.loads(a["evidence"] or "{}")
        for k in (
            "bytes_estimated",
            "objects_prefix",
            "amount_mentioned",
            "personal_data_matches",
            "file",
            "destination",
        ):
            if ev.get(k):
                data_bits.append(f"{k}={ev[k]}")
    exfil = [
        s
        for s in steps
        if s["tid"] and (s["tid"].startswith("T1567") or s["tid"].startswith("T1048") or s["tid"] == "T1530")
    ]
    scope = {
        "users": sorted(P["users"]),
        "hosts": sorted(P["hosts"]),
        "customers": sorted(P["customers"])[:50],
        "attacker_ips": sorted(P["ips"])[:40],
        "domains": sorted(P["domains"]),
        "hashes": sorted(P["hashes"]),
        "data": "; ".join(dict.fromkeys(data_bits))[:400]
        or ("possible exfiltration observed" if exfil else "no data movement observed"),
        "business_impact": "; ".join(svc) or "customer-facing e-commerce" if P["customers"] else "; ".join(svc),
    }
    tl = sorted(
        dict.fromkeys(tactics),
        key=lambda t: min(
            X.mitre[s["tid"]][2] or 99 for s in steps if s["tid"] in X.mitre and X.mitre[s["tid"]][1] == t
        ),
    )
    root = (
        f'{X.mitre.get(ia["tid"], ("unknown",))[0]} ({ia["tid"]}) - first victim {pz} - on {ia["t"]:%Y-%m-%d %H:%M} UTC; '
        f'progressed through {", ".join(tl)}; reached {len(P["hosts"])} host(s), {len(P["users"])} account(s)'
        + (f', {len(P["customers"])} customer account(s)' if P["customers"] else "")
        + f". {len(hidden)} step(s) found only in raw logs (not alerted)."
    )
    # containment proposal (policy s.4 approvers) - executed only with human approval (L4)
    plan = []
    for ip in sorted(P["ips"])[:15]:
        plan.append({"action": "block_ioc", "target": ip, "approver": "N1 (execute)", "business_impact": "none"})
    for dm in sorted(P["domains"])[:10]:
        dual = any(x in dm for x in ("mega.nz", "anydesk", "wetransfer", "dropbox"))
        plan.append(
            {
                "action": "block_ioc",
                "target": dm,
                "approver": "N2" if dual else "N1 (execute)",
                "business_impact": "dual-use service: global block needs N2" if dual else "none",
            }
        )
    for hs in sorted(P["hashes"])[:10]:
        plan.append({"action": "block_ioc", "target": hs, "approver": "N1 (execute)", "business_impact": "none"})
    for rf in sorted(r for r in P["refs"] if r.startswith("<")):
        plan.append({"action": "purge_email", "target": rf, "approver": "N1 (execute)", "business_impact": "none"})
    created = {nuser(s["ev"]["dst"]) for s in steps if s["ev"] is not None and s["tid"] in ("T1136.002", "T1136.003")}
    for u in sorted(P["users"]):
        r = X.users.get(u)
        if u in created:
            plan.append(
                {
                    "action": "disable_user (then delete)",
                    "target": u,
                    "approver": "N2",
                    "business_impact": "attacker-created account: none",
                }
            )
        elif r is None:
            plan.append(
                {
                    "action": "disable_user",
                    "target": u,
                    "approver": "N2",
                    "business_impact": "account not in directory (created by attacker?)",
                }
            )
        elif r["account_type"] == "service":
            plan.append(
                {
                    "action": "disable_user",
                    "target": u,
                    "approver": "N2",
                    "business_impact": "service account: may stop a business process",
                }
            )
        else:
            plan.append(
                {
                    "action": "revoke_sessions + reset_password",
                    "target": u,
                    "approver": "N2",
                    "business_impact": "user loses sessions",
                }
            )
    for h in sorted(P["hosts"]):
        a = X.assets.get(h)
        if not a:
            continue
        zone, typ = (a["zone"] or ""), (a["type"] or "")
        if "OT" in zone:
            plan.append(
                {
                    "action": "escalate only (no action on OT)",
                    "target": h,
                    "approver": "Operations manager",
                    "business_impact": a["business_service"],
                }
            )
        elif h.startswith(("POS", "TPV", "WEB")):
            plan.append(
                {
                    "action": "isolate_host",
                    "target": h,
                    "approver": "N2 + business",
                    "business_impact": f'sales impact: {a["business_service"]}',
                }
            )
        elif typ.lower().startswith(("serv", "srv")) or not h.startswith("WS-"):
            plan.append(
                {
                    "action": "isolate_host",
                    "target": h,
                    "approver": f'N2 + service owner ({a["service_responsable"] or a["owner_upn"] or "IT infrastructure owner"})',
                    "business_impact": a["business_service"],
                }
            )
        else:
            plan.append(
                {"action": "isolate_host", "target": h, "approver": "N2", "business_impact": "user workstation"}
            )
    for rf in sorted(r for r in P["refs"] if r.startswith("AKIA")):
        plan.append(
            {
                "action": "disable_access_key",
                "target": rf,
                "approver": "N2",
                "business_impact": "deployments using the key stop",
            }
        )
    notif = ["Responsable SOC (escalation, policy s.3)"]
    sev = inc["final_severity"]
    if sev == "critical":
        notif.append("CISO - immediately (critical)")
    if exfil or any("personal data" in (inc["escalation_reasons"] or "") for _ in [0]):
        notif.append("DPO - personal data may have left (GDPR breach assessment, 72 h to AEPD)")
    if any(a["rule_id"] in ("UC-EML-004", "UC-WEB-003") for a in alerts) or any(s["tid"] == "T1657" for s in steps):
        notif.append("Tesoreria / e-commerce fraud team - hold payments, block gift cards")
    if any(
        (X.assets.get(h) or {"business_service": ""})["business_service"] and "PCI" in X.assets[h]["business_service"]
        for h in P["hosts"]
        if h in X.assets
    ):
        notif.append("PCI acquirer - possible cardholder-data compromise")
    erad = []
    if any(s["tid"] == "T1547.001" for s in steps):
        erad.append("Remove Run-key persistence and dropped payloads; reimage affected workstation(s)")
    if any(s["tid"] in ("T1136.002", "T1136.003", "T1098.007", "T1098.001") for s in steps):
        erad.append("Delete attacker-created accounts/keys and review privileged group membership")
    if any(s["tid"] == "T1564.008" for s in steps):
        erad.append("Delete malicious inbox rules and review mail forwarding")
    if any(s["tid"] in ("T1003.001", "T1555.003") for s in steps):
        erad.append(
            "Reset every credential exposed on the host (incl. cached admin accounts); consider krbtgt double reset"
        )
    if any(s["tid"] == "T1490" for s in steps):
        erad.append("Verify backup integrity before recovery (shadow copies / catalog deleted)")
    if any(s["tid"] == "T1530" for s in steps):
        erad.append("Rotate cloud credentials, restrict bucket policies, review data accessed")
    erad.append("Monitor all scope entities for 30 days; hunt the IOCs across the estate")
    gaps = sorted(
        {
            f'{X.mitre[s["tid"]][0]} ({s["tid"]}) seen only in raw {s["ev"]["source"]} logs: create/tune a rule'
            for s in hidden
            if s["tid"] in X.mitre and s["ev"] is not None
        }
    )[:10]
    openq = []
    unknown = [i for i in P["ips"] if i not in X.geo or not X.geo[i]["reputation"]]
    if unknown:
        openq.append(f"{len(unknown)} attacker IP(s) unknown to the TIP (unknown != clean): enrich with OSINT")
    if exfil:
        openq.append("Exact volume and content of the data that left must be confirmed with the data owner")
    if not any(s["tid"] in X.mitre and X.mitre[s["tid"]][1] == "Initial Access" for s in steps):
        openq.append("Initial access vector not observed in the available logs")
    openq.append("Human validation required before containment (proposed, not executed)")
    distinct_t = len(set(tactics))
    impact = any(
        s["tid"] and s["tid"].startswith(("T1567", "T1048", "T1530", "T1657", "T1486", "T1490", "T1213")) for s in steps
    )
    conf = min(
        0.95,
        0.4
        + 0.07 * distinct_t
        + (0.1 if any(X.malicious(x) for x in P["ips"] | P["domains"] | P["hashes"]) else 0)  # TIP / sandbox confirmed
        + (0.1 if hidden else 0)  # corroborated in raw logs
        + (0.1 if impact else 0),
    )  # data movement / impact observed
    return dict(
        inc=inc,
        alerts=alert_ids,
        steps=steps,
        P=P,
        tactics=distinct_t,
        kco=kco,
        ia=ia,
        pz=pz,
        scope=scope,
        root=root,
        plan=plan,
        notif=notif,
        erad=erad,
        gaps=gaps,
        openq=openq,
        conf=round(conf, 2),
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="tarvia_soc.sqlite")
    ap.add_argument("--incident", action="append")
    ap.add_argument("--status", default="escalate_n2")
    ap.add_argument("--reports", default="reports")
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=OFF")
    cols = [r[1] for r in con.execute("PRAGMA table_info(fact_incident)")]
    for c in ("eradication_and_recovery", "notifications", "detection_gaps", "related_incidents"):
        if c not in cols:
            con.execute(f"ALTER TABLE fact_incident ADD COLUMN {c} TEXT")
    X = Ctx(con)
    ids = a.incident or [
        r[0]
        for r in con.execute("SELECT incident_id FROM fact_incident WHERE status=? ORDER BY first_seen", (a.status,))
    ]
    out = pathlib.Path(a.reports)
    out.mkdir(parents=True, exist_ok=True)
    results = {}
    for iid in ids:
        results[iid] = investigate(con, X, iid)
    # related incidents: other incidents sharing investigation pivots (users, hosts, attacker IPs, IOCs)
    ent_idx = collections.defaultdict(set)
    for r in con.execute("""SELECT b.incident_id, e.entity_type, e.entity_value, e.user_key, e.hostname, i.status
                            FROM bridge_alert_incident b JOIN bridge_alert_entity e USING(alert_id)
                            JOIN fact_incident i USING(incident_id) WHERE i.status != 'auto_closed_btp'"""):
        v = r["user_key"] or r["hostname"] or r["entity_value"]
        strong = r["entity_type"] in ("ip", "domain", "file", "url", "access_key")
        if strong or r["status"] in ("escalate_n2", "priority_triage"):
            ent_idx[v].add(r["incident_id"])
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for iid, R in results.items():
        piv = (
            R["P"]["users"]
            | R["P"]["hosts"]
            | R["P"]["ips"]
            | R["P"]["customers"]
            | {d for d in R["P"]["domains"] if X.attacker_domain(d)}
            | {h for h in R["P"]["hashes"] if X.rare_hash(h)}
        )
        rel = collections.Counter(i for v in sorted(piv) for i in sorted(ent_idx.get(v, ())) if i != iid)
        related = [i for i, _ in rel.most_common(15)]
        R["related"] = related
        con.execute("DELETE FROM fact_attack_step WHERE incident_id=?", (iid,))
        for n, s in enumerate(R["steps"], 1):
            ev = s["ev"]
            con.execute(
                """INSERT INTO fact_attack_step(incident_id,step_order,timestamp,event_id,alert_id,technique_id,user_key,hostname,
                           context_key,evidence_origin,description,confidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    iid,
                    n,
                    iso(s["t"]),
                    ev["event_id"] if ev is not None else None,
                    s["alert"],
                    s["tid"] if s["tid"] in X.mitre else None,
                    (ev["user_key"] if ev is not None else s.get("user")),
                    (ev["hostname"] if ev is not None else s.get("host")),
                    None,
                    s["origin"],
                    s["desc"] + (f" (x{s['n']} events until {iso(s['last'])})" if s["n"] > 1 else ""),
                    0.9 if s["origin"] == "alert" else (0.7 if s["origin"] == "hidden_log" else 0.6),
                ),
            )
        verdict = "true_positive" if R["conf"] >= 0.7 else "needs_more_info"
        con.execute(
            """UPDATE fact_incident SET patient_zero=?, initial_access=?, scope=?, root_cause=?, containment_plan=?,
                       open_questions=?, confidence=?, tactics_covered=?, max_kill_chain_stage=?, verdict=?, triage_stage='L3',
                       related_incident_id=?, related_incidents=?, eradication_and_recovery=?, notifications=?, detection_gaps=?,
                       updated_at=? WHERE incident_id=?""",
            (
                R["pz"],
                R["ia"]["tid"] if R["ia"]["tid"] in X.mitre else None,
                json.dumps(R["scope"], ensure_ascii=False),
                R["root"],
                json.dumps(R["plan"], ensure_ascii=False),
                json.dumps(R["openq"], ensure_ascii=False),
                R["conf"],
                R["tactics"],
                R["kco"],
                verdict,
                related[0] if related else None,
                json.dumps(related),
                json.dumps(R["erad"], ensure_ascii=False),
                json.dumps(R["notif"], ensure_ascii=False),
                json.dumps(R["gaps"], ensure_ascii=False),
                now,
                iid,
            ),
        )
        report = {
            "incident_id": iid,
            "title": R["inc"]["title"],
            "alert_ids": R["alerts"],
            "related_incidents": related,
            "patient_zero": R["pz"],
            "initial_access": f'{R["ia"]["tid"]} {X.mitre.get(R["ia"]["tid"], ("",))[0]}'.strip(),
            "timeline": [
                {
                    "timestamp": iso(s["t"]),
                    "event_id": (s["ev"]["event_id"] if s["ev"] is not None else (s["alert"] or "context")),
                    "description": f'[{s["origin"]}] ' + s["desc"] + (f" (x{s['n']})" if s["n"] > 1 else ""),
                    "mitre": s["tid"] or "",
                }
                for s in R["steps"]
            ],
            "scope": R["scope"],
            "root_cause": R["root"],
            "containment_plan": R["plan"],
            "eradication_and_recovery": R["erad"],
            "notifications": R["notif"],
            "detection_gaps": R["gaps"],
            "confidence": R["conf"],
            "open_questions": R["openq"],
        }
        (out / f"{iid}.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        o = collections.Counter(s["origin"] for s in R["steps"])
        print(
            f'{iid}: steps={len(R["steps"])} (alert {o["alert"]}, hidden {o["hidden_log"]}, context {o["context"]}) '
            f'tactics={R["tactics"]} stage={R["kco"]} pz={R["pz"]} IA={R["ia"]["tid"]} conf={R["conf"]} related={related[:4]}'
        )
    con.commit()


if __name__ == "__main__":
    main()
