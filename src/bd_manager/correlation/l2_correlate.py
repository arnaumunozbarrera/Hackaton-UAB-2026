"""
Tarvia SOC - L2 "triage with judgement" (deterministic, explainable).

  1. Authorised activity  -> benign_true_positive (approved changes / flows + HR context)
  2. Final severity       -> policy matrix (rule severity x most critical asset) with max +-1 adjustment
  3. Correlation          -> duplicates, campaigns, shared entities (24 h) and persistent malicious IOCs
  4. Incidents            -> one ticket per intrusion, kill-chain coverage, mandatory escalation (policy s.5)

Re-runnable: clears L2 outputs and recomputes.   Usage: python l2_correlate.py --db tarvia_soc.sqlite
The LLM agent (L1 verdict) works on top of this: it receives incidents, not isolated alerts.
"""

import argparse
import collections
import json
import re
import sqlite3
import unicodedata
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

MAD = ZoneInfo("Europe/Madrid")
SEV = ["informational", "low", "medium", "high", "critical"]
CRIT = {"Baja": 1, "Media": 2, "Alta": 3, "Crítica": 4}
CRIT_NAME = {v: k for k, v in CRIT.items()}

# ---- policy-derived knowledge (configurable) -------------------------------------------------
EFFECT_RULES = {  # detection implies access/execution actually happened
    "UC-IDP-004",
    "UC-IDP-005",
    "UC-IDP-006",
    "UC-IDP-007",
    "UC-IDP-008",
    "UC-CLD-002",
    "UC-CLD-004",
    "UC-WEB-003",
    "UC-EML-003",
    "UC-EDR-004",
    "UC-EDR-006",
    "UC-EDR-007",
    "UC-EDR-009",
    "UC-EDR-010",
    "UC-EDR-012",
    "UC-DEV-001",
}
PII_PAYMENT_RULES = {"UC-DLP-001", "UC-DLP-002", "UC-EML-004", "UC-WEB-003", "UC-AI-002", "UC-CLD-004", "UC-EDR-012"}
FRAUD_RULES = {"UC-EML-004", "UC-WEB-003"}
CRED_THEFT_RULES = {"UC-EDR-004", "UC-EDR-010", "UC-IDP-003", "UC-IDP-006", "UC-EML-003"}
PRODUCT_CRITICALITY = {"WAF": 4, "ECOM": 4, "AI_GATEWAY": 3}  # customer-facing services (servicios_negocio.csv)
# Changes whose text has no machine-matchable token: extra tokens (rule ids or structured values)
CHANGE_EXTRA_TOKENS = {
    "CHG-2026-1031": ["svc_sccm", "CcmExec"],
    "CHG-2026-1066": ["VPN-GW01", "UC-VPN-001"],
    "CHG-2026-1078": ["Backup Operators"],
    "CHG-2026-1080": ["UC-EDR-011"],
}
# Only structured evidence keys may authorise an alert. Free text (subject, prompt, decoded commands...)
# is attacker-controllable and must never whitelist anything.
TRUSTED_EVIDENCE_KEYS = {
    "src_ip",
    "src",
    "source",
    "parent",
    "parent_chain",
    "user",
    "account",
    "destination",
    "recipient",
    "dst",
    "dst_ip",
    "created_from_ip",
    "process",
    "device",
    "app",
    "group",
    "submitted_from_ip",
    "account_type",
    "signer",
    "change_ticket",
}
BLOCK_VALUES = {"blocked", "quarantined", "denied"}
HUB_THRESHOLD = 25  # same (entity, rule) in more alerts than this = campaign
WINDOW = timedelta(hours=24)
DAILY_TOLERANCE_MIN = 10  # recurring jobs drift a few minutes past the approved window
BURST_GAP = timedelta(hours=6)  # same rule, no internal entity (credential stuffing / spraying waves)
SCORES = {
    "duplicate": 1.0,
    "message_id": 0.95,
    "session": 0.95,
    "file": 0.95,
    "malicious_ioc": 0.9,
    "campaign": 0.85,
    "user": 0.75,
    "host": 0.75,
    "cloud_identity": 0.8,
    "customer": 0.7,
    "ip": 0.6,
    "domain": 0.7,
    "url": 0.65,
    "access_key": 0.9,
    "ai_session": 0.9,
    "bucket": 0.6,
}
PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def norm(s):
    return unicodedata.normalize("NFKD", str(s)).encode("ascii", "ignore").decode().lower()


def local_to_utc(s):
    return datetime.strptime(s, "%Y-%m-%d %H:%M").replace(tzinfo=MAD).astimezone(timezone.utc)


class UF:
    def __init__(s):
        s.p = {}

    def f(s, x):
        s.p.setdefault(x, x)
        while s.p[x] != x:
            s.p[x] = s.p[s.p[x]]
            x = s.p[x]
        return x

    def u(s, a, b):
        a, b = s.f(a), s.f(b)
        if a != b:
            s.p[max(a, b)] = min(a, b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="tarvia_soc.sqlite")
    ap.add_argument(
        "--force", action="store_true", help="also discard tickets / analyst decisions linked to old incidents"
    )
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=OFF")
    q = lambda s, *p: con.execute(s, p).fetchall()
    for col, typ in (("escalation_reasons", "TEXT"), ("authorised_by", "TEXT"), ("triage_stage", "TEXT")):
        if col not in [r[1] for r in q("PRAGMA table_info(fact_incident)")]:
            con.execute(f"ALTER TABLE fact_incident ADD COLUMN {col} {typ}")
    if "authorised_by" not in [r[1] for r in q("PRAGMA table_info(fact_alert)")]:
        con.execute("ALTER TABLE fact_alert ADD COLUMN authorised_by TEXT")

    # ---------------- load
    A = {}
    for r in q("""SELECT a.alert_id, a.created_at, a.rule_id, a.rule_severity, a.source_product, a.evidence,
                         a.dedup_hash, a.rule_name, m.tactic, m.kill_chain_order
                  FROM fact_alert a LEFT JOIN dim_mitre m ON m.technique_id = a.technique_id"""):
        A[r["alert_id"]] = dict(
            id=r["alert_id"],
            t=ts(r["created_at"]),
            rule=r["rule_id"],
            rsev=r["rule_severity"],
            prod=r["source_product"],
            ev=json.loads(r["evidence"] or "{}"),
            dedup=r["dedup_hash"],
            rname=r["rule_name"],
            tactic=r["tactic"],
            kco=r["kill_chain_order"],
            ents=[],
        )
    for r in q("SELECT alert_id, entity_type, entity_value, user_key, hostname, context_key FROM bridge_alert_entity"):
        A[r[0]]["ents"].append((r[1], r[2], r[3], r[4], r[5]))
    users = {r["user_key"]: r for r in q("SELECT * FROM dim_user")}
    hostcrit = {r[0]: r[1] for r in q("SELECT hostname, criticality_level FROM dim_vulnerability")}
    hostzone = {r[0]: (r[1] or "") for r in q("SELECT hostname, zone FROM dim_vulnerability")}
    malicious = {
        r[0]
        for r in q("""SELECT context_key FROM dim_context
                                    WHERE reputation='malicious' OR sandbox_verdict='malicious'""")
    }
    changes = q("SELECT * FROM dim_context WHERE context_type='change'")
    order = sorted(A.values(), key=lambda x: x["t"])

    # ---------------- 1. authorised activity
    def trusted_text(x):
        parts = [x["rule"] or ""] + [e[1] for e in x["ents"]]
        for k, v in x["ev"].items():
            if k in TRUSTED_EVIDENCE_KEYS:
                parts.append(json.dumps(v, ensure_ascii=False))
        return " | ".join(parts)

    def expand(tok):
        m = re.match(r"^(.*?)(\d+)\.\.(\d+)$", tok)
        if m:
            return [f"{m.group(1)}{i:0{len(m.group(2))}d}" for i in range(int(m.group(2)), int(m.group(3)) + 1)]
        return [tok]

    matchers = []
    for c in changes:
        text = f'{c["change_title"]} {c["change_detail"]} {c["change_scope"]}'
        toks = set()
        for m in re.finditer(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})\b", text):
            toks |= {f"{m.group(1)}{i}" for i in range(int(m.group(2)), int(m.group(3)) + 1)}
        toks |= {x for t in re.findall(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*\d+(?:\.\.\d+)?\b", text) for x in expand(t)}
        toks |= set(re.findall(r"\b(?:svc_[a-z0-9_]+|ext\.[a-z0-9_.]+)\b", text))
        toks |= set(re.findall(r"[\w.-]+@[\w.-]+\.\w+", text))
        toks |= set(CHANGE_EXTRA_TOKENS.get(c["context_key"], []))
        toks = {t for t in toks if not re.fullmatch(r"(CHG|FLUJO)-[\d-]+", t)}
        start, end = local_to_utc(c["change_start"]), local_to_utc(c["change_end"])
        daily = re.search(r"diariamente\s+(\d{2}):(\d{2})-(\d{2}):(\d{2})", c["change_detail"] or "")
        matchers.append(
            dict(
                id=c["context_key"],
                title=c["change_title"],
                toks=toks,
                start=start,
                end=end,
                daily=daily,
                no_ot="salvo OT" in (c["change_scope"] or ""),
            )
        )
    hr = []
    for u in users.values():
        if u["hr_event"] not in ("viaje", "teletrabajo_temporal"):
            continue
        det = u["hr_detalle"] or ""
        m = re.search(r"del (\d{1,2})/(\d{1,2}) al (\d{1,2})/(\d{1,2})", det)
        if m:
            s = datetime(2026, int(m.group(2)), int(m.group(1)), tzinfo=MAD)
            e = datetime(2026, int(m.group(4)), int(m.group(3)), 23, 59, tzinfo=MAD)
        else:
            s = datetime.fromisoformat(u["hr_fecha_efectiva"]).replace(tzinfo=MAD)
            e = s + timedelta(days=14)
        cities = [norm(x) for x in re.findall(r"[A-ZÁÉÍÓÚ][a-záéíóúñ]+(?: [A-Z][a-z]+)?", det) if len(x) > 3]
        hr.append(dict(user=u["user_key"], kind=u["hr_event"], start=s, end=e, cities=cities, det=det))

    btp = {}
    for x in order:
        txt = norm(trusted_text(x))
        for mt in matchers:
            if not (mt["start"] <= x["t"] <= mt["end"]):
                continue
            if mt["daily"]:
                lt = x["t"].astimezone(MAD)
                h1, m1, h2, m2 = map(int, mt["daily"].groups())
                mins = lt.hour * 60 + lt.minute
                if not (h1 * 60 + m1 - DAILY_TOLERANCE_MIN <= mins <= h2 * 60 + m2 + DAILY_TOLERANCE_MIN):
                    continue
            if mt["no_ot"] and any("OT" in hostzone.get(e[3] or "", "") for e in x["ents"]):
                continue
            hit = next(
                (t for t in sorted(mt["toks"]) if re.search(r"(?<![\w.])" + re.escape(norm(t)) + r"(?![\w])", txt)),
                None,
            )
            if hit:
                btp[x["id"]] = (mt["id"], f'approved change {mt["id"]} "{mt["title"]}" (window match + "{hit}")')
                break
        if x["id"] in btp or x["rule"] not in ("UC-IDP-001", "UC-IDP-004", "UC-VPN-001"):
            continue
        uks = {e[2] for e in x["ents"] if e[2]}
        cities = norm(" ".join(str(x["ev"].get(k, "")) for k in ("current_login", "src_city", "city", "user_location")))
        for h in hr:
            if h["user"] in uks and h["start"] <= x["t"] <= h["end"] and any(cty in cities for cty in h["cities"]):
                btp[x["id"]] = (
                    f'HR:{h["user"]}',
                    f'HR event "{h["kind"]}" of {h["user"]} covers the login location ({h["det"][:60]})',
                )
                break

    # ---------------- entity index (for "no posterior activity" and linking)
    def link_keys(x):
        keys = []
        for typ, val, uk, hn, ck in x["ents"]:
            if typ == "user" and uk:
                keys.append(("user", uk))
            elif typ == "host" and hn:
                keys.append(("host", hn))
            elif typ == "ip" and not PRIVATE.match(val):
                keys.append(("ip", val))
            elif typ in ("domain", "url", "file", "customer", "cloud_identity", "bucket", "access_key", "ai_session"):
                keys.append((typ, val))
        for k in ("message_id", "session_id"):
            if x["ev"].get(k):
                keys.append(("message_id" if k == "message_id" else "session", str(x["ev"][k])))
        return keys

    for x in order:
        x["keys"] = link_keys(x)
    by_key = collections.defaultdict(list)
    for x in order:
        for k in dict.fromkeys(x["keys"]):
            by_key[k].append(x)

    # ---------------- 2. final severity per alert
    for x in order:
        lvl = (
            max([hostcrit.get(e[3], 0) for e in x["ents"] if e[3]] + [PRODUCT_CRITICALITY.get(x["prod"], 0)] or [0])
            or 2
        )
        base = SEV.index(
            con.execute(
                "SELECT base_severity FROM ref_severity_matrix WHERE rule_severity=? AND criticality=?",
                (x["rsev"], CRIT_NAME[lvl]),
            ).fetchone()[0]
        )
        up, down = [], []
        ev = x["ev"]
        blocked = (
            str(ev.get("action", "")).lower() in BLOCK_VALUES
            or ev.get("edr_action") == "blocked"
            or ev.get("tool_result") == "denied"
        )
        confirmed = (
            x["rule"] in EFFECT_RULES
            or ev.get("executed") is True
            or ev.get("credentials_submitted") is True
            or (isinstance(ev.get("success_count"), int) and ev["success_count"] > 0)
            or (isinstance(ev.get("successes"), int) and ev["successes"] > 0)
            or "approved" in (str(ev.get("mfa_result")), str(ev.get("final_result")))
        )
        if confirmed and not blocked:
            up.append("execution/access confirmed")
        vip = [
            e[2]
            for e in x["ents"]
            if e[2]
            and e[2] in users
            and (users[e[2]]["vip"] or users[e[2]]["privileged"] or users[e[2]]["account_type"] == "admin")
        ]
        if vip:
            up.append(f"VIP/privileged identity ({', '.join(sorted(set(vip)))})")

        def truthy(v):
            if isinstance(v, dict):
                return any(truthy(z) for z in v.values())
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                return v > 0
            return bool(v) and str(v).lower() not in ("0", "false", "none", "no")

        explicit_zero = "personal_data_matches" in ev and not truthy(ev["personal_data_matches"])
        pii = (x["rule"] in PII_PAYMENT_RULES and not explicit_zero) or any(
            truthy(ev.get(k)) for k in ("personal_data_matches", "matches", "amount_mentioned", "new_iban_country")
        )
        if pii:
            up.append("personal data or payments involved")
        if blocked:
            later = any(
                y["t"] > x["t"] and y["t"] - x["t"] <= WINDOW and y["id"] != x["id"]
                for k in x["keys"]
                if k[0] in ("user", "host", "ip") and len(by_key[k]) <= HUB_THRESHOLD
                for y in by_key[k]
                if y["rule"] != x["rule"]
            )
            if not later:
                down.append("blocked by a control, no later activity (24 h)")
        adj = (1 if up else 0) - (1 if down else 0)
        final = SEV[min(4, max(0, base + adj))]
        rat = f'matrix({x["rsev"]} x {CRIT_NAME[lvl]}) = {SEV[base]}'
        if up:
            rat += "; +1: " + ", ".join(up)
        if down:
            rat += "; -1: " + ", ".join(down)
        if up and down:
            rat += " (net 0)"
        x.update(final=final, rat=rat, confirmed=confirmed and not blocked, pii=pii and not blocked, blocked=blocked)
        if x["id"] in btp:
            ref, why = btp[x["id"]]
            x.update(
                final="low" if x["rsev"] in ("high", "critical") else "informational",
                rat=f"benign_true_positive: {why}; policy s.2 -> informational/low",
                authorised=ref,
            )
        else:
            x["authorised"] = None

    # ---------------- 3. correlation
    uf, best = UF(), {}

    def link(x, y, reason, score):
        uf.u(x["id"], y["id"])
        for z in (x, y):
            if score > best.get(z["id"], ("", 0, ""))[1]:
                best[z["id"]] = (
                    reason,
                    score,
                    "24h" if reason not in ("malicious_ioc", "authorised") else "entity_persistent",
                )

    for x in order:
        uf.f(x["id"])
    # 3a authorised activity: one incident per change / HR event
    groups = collections.defaultdict(list)
    for x in order:
        if x["authorised"]:
            groups[x["authorised"]].append(x)
    for g in groups.values():
        for y in g[1:]:
            link(g[0], y, "authorised", 1.0)
    # 3b duplicates
    dd = collections.defaultdict(list)
    for x in order:
        if not x["authorised"]:
            dd[x["dedup"]].append(x)
    dup = set()
    for g in dd.values():
        for y in g[1:]:
            link(g[0], y, "duplicate", 1.0)
            dup.add(y["id"])
    # 3c campaigns: same rule + hub entity -> only the campaign key links the alert
    rule_key_count = collections.Counter(
        (k, x["rule"]) for x in order if not x["authorised"] for k in dict.fromkeys(x["keys"])
    )
    prio = {"ip": 0, "domain": 1, "file": 2, "cloud_identity": 3, "bucket": 4, "url": 5}
    for x in order:
        hubs = [k for k in dict.fromkeys(x["keys"]) if rule_key_count[(k, x["rule"])] > HUB_THRESHOLD and k[0] in prio]
        # high/critical alerts are never absorbed by a campaign: they stay visible and link by their own entities
        x["campaign"] = (
            min(hubs, key=lambda k: (prio[k[0]], k[1]))
            if hubs and not x["authorised"] and SEV.index(x["final"]) <= 2
            else None
        )
    camp = collections.defaultdict(list)
    for x in order:
        if x["campaign"]:
            camp[(x["campaign"], x["rule"])].append(x)
    for g in camp.values():
        for p, y in zip(g, g[1:], strict=False):
            if y["t"] - p["t"] <= WINDOW:
                link(p, y, "campaign", SCORES["campaign"])
    # 3d shared entities within 24 h (campaign members only through their campaign key)
    for k, xs in by_key.items():
        xs = [x for x in xs if not x["authorised"]]
        hub = len({x["rule"] for x in xs}) and sum(1 for _ in xs) > HUB_THRESHOLD
        for i, x in enumerate(xs):
            for y in xs[i + 1 :]:
                if y["t"] - x["t"] > WINDOW:
                    break
                if x["rule"] == y["rule"] and x["dedup"] == y["dedup"]:
                    continue
                cx, cy = x["campaign"], y["campaign"]
                if (cx and cx != k) or (cy and cy != k):
                    continue  # campaign members link only by campaign key
                if hub and x["rule"] == y["rule"]:
                    continue  # handled in 3c
                if hub and not (SEV.index(x["final"]) >= 2 or SEV.index(y["final"]) >= 2):
                    continue  # hub: only follow-ons
                link(x, y, k[0], SCORES.get(k[0], 0.6))
    # 3d' rule bursts: same rule, no resolved internal user/host, gap <= BURST_GAP (customer-facing / external waves)
    rb = collections.defaultdict(list)
    for x in order:
        if not x["authorised"] and not x["campaign"] and not any(e[2] or e[3] for e in x["ents"]):
            rb[x["rule"]].append(x)
    for g in rb.values():
        for p, y in zip(g, g[1:], strict=False):
            if y["t"] - p["t"] <= BURST_GAP:
                link(p, y, "rule_burst", 0.5)
    # 3e persistent link: same known-malicious IOC / file / message across days
    for k, xs in by_key.items():
        if k[0] in ("file", "domain", "url", "ip") and k[1] in malicious:
            xs = [x for x in xs if not x["authorised"]]
            for p, y in zip(xs, xs[1:], strict=False):
                link(p, y, "malicious_ioc", SCORES["malicious_ioc"])

    # ---------------- 4. incidents
    comps = collections.defaultdict(list)
    for x in order:
        comps[uf.f(x["id"])].append(x)
    # A new L2 run regenerates every incident id: previous L3 results are discarded (re-run l3_reconstruct.py afterwards).
    human = [
        t
        for t in ("analyst_decision", "proposed_action", "fact_ticket", "llm_tool_call", "llm_run")
        if q("SELECT name FROM sqlite_master WHERE type='table' AND name=?", t) and q(f"SELECT COUNT(*) FROM {t}")[0][0]
    ]
    if human and not a.force:
        raise SystemExit(f"refusing to regenerate incidents: {human} contain analyst work linked to them (use --force)")
    for t in human:
        con.execute(f"DELETE FROM {t}")
    con.execute("DELETE FROM fact_attack_step")
    con.execute("DELETE FROM bridge_alert_incident")
    con.execute("DELETE FROM fact_incident")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    inc_rows, br_rows, al_rows = [], [], []
    comps_sorted = sorted(comps.values(), key=lambda g: g[0]["t"])
    first_by_entity = {}
    for n, g in enumerate(comps_sorted, 1):
        iid = f"INC-{g[0]['t']:%Y%m%d}-{n:05d}"
        live = [x for x in g if not x["authorised"]]
        tactics = {x["tactic"] for x in live if x["tactic"]}
        kco = max([x["kco"] for x in live if x["kco"]] or [None]) if live else None
        sev = max(SEV.index(x["final"]) for x in g)
        reasons = []
        chain = len(tactics) >= 3
        if chain:
            sev = min(4, sev + 1)
            reasons.append(f"attack chain across {len(tactics)} tactics ({', '.join(sorted(tactics))})")
        if any(x["confirmed"] and x["tactic"] == "Execution" for x in live):
            reasons.append("confirmed execution")
        if any(x["rule"] in CRED_THEFT_RULES and not x["blocked"] for x in live):
            reasons.append("possible credential theft")
        if any(x["pii"] for x in live):
            reasons.append("personal data may have left the organisation (DPO)")
        if any(x["rule"] in FRAUD_RULES for x in live):
            reasons.append("economic fraud")
        uc = collections.Counter(e[2] for x in g for e in x["ents"] if e[2])
        hc = collections.Counter(e[3] for x in g for e in x["ents"] if e[3])
        pu, ph = (uc.most_common(1)[0][0] if uc else None), (hc.most_common(1)[0][0] if hc else None)
        rule_top = collections.Counter(x["rname"] for x in g).most_common(1)[0][0]
        ctx_notes = [
            f'{u} HR: {users[u]["hr_event"]} (effective {users[u]["hr_fecha_efectiva"]})'
            for u in uc
            if u in users and users[u]["hr_event"] in ("baja_voluntaria_comunicada", "cambio_puesto", "alta")
        ]
        if not live:
            auth = g[0]["authorised"]
            verdict, status = "benign_true_positive", "auto_closed_btp"
            title = f"Authorised activity ({auth}): {rule_top} x{len(g)}"
        else:
            auth = None
            verdict = None
            # escalate_n2   : mandatory criteria of policy s.5 already met by the evidence
            # priority_triage: high/critical, escalate only if the L1 verdict is true_positive (SLA 15/30 min)
            status = (
                "escalate_n2"
                if reasons
                else "priority_triage"
                if sev >= 3
                else "pending_triage"
                if sev == 2
                else "batch_review"
            )
            ck = collections.Counter(x["campaign"] for x in g if x["campaign"]).most_common(1)
            ent = (
                (f"campaign {ck[0][0][0]}={ck[0][0][1]}" if ck and ck[0][1] > len(g) / 2 else None)
                or pu
                or ph
                or next((e[1] for e in g[0]["ents"]), "")
            )
            title = f"{rule_top}" + (f" - {ent}" if ent else "") + (f" (+{len(g)-1} alerts)" if len(g) > 1 else "")
        related = None
        for key in ((("user", pu),) if pu else ()) + ((("host", ph),) if ph else ()):
            if key in first_by_entity and first_by_entity[key] != iid:
                related = related or first_by_entity[key]
            first_by_entity.setdefault(key, iid)
        inc_rows.append(
            (
                iid,
                title[:200],
                g[0]["t"].isoformat(),
                g[-1]["t"].isoformat(),
                len(g),
                pu if pu in users else None,
                ph if ph in hostcrit else None,
                len(tactics),
                kco,
                verdict,
                SEV[sev],
                "max alert severity"
                + (" +1 (attack chain, policy s.5)" if chain else "")
                + (("; context: " + "; ".join(ctx_notes)) if ctx_notes else ""),
                0.9 if verdict else None,
                1 if status == "escalate_n2" else 0,
                status,
                related,
                now,
                now,
                "; ".join(reasons) or None,
                auth,
                "L2",
            )
        )
        for x in g:
            r = best.get(x["id"], ("seed", 1.0, None))
            br_rows.append((x["id"], iid, r[0], r[2], r[1], 1 if x["id"] in dup else 0, 1 if x["authorised"] else 0))
            al_rows.append(
                (
                    x["final"],
                    x["rat"],
                    "benign_true_positive" if x["authorised"] else None,
                    0.9 if x["authorised"] else None,
                    "close" if x["authorised"] else ("escalate" if status == "escalate_n2" else None),
                    now,
                    x["authorised"],
                    x["id"],
                )
            )
    con.executemany(
        """INSERT INTO fact_incident(incident_id,title,first_seen,last_seen,alert_count,primary_user_key,primary_hostname,
        tactics_covered,max_kill_chain_stage,verdict,final_severity,severity_rationale,confidence,escalate_n2,status,
        related_incident_id,created_at,updated_at,escalation_reasons,authorised_by,triage_stage)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        inc_rows,
    )
    con.executemany("INSERT INTO bridge_alert_incident VALUES (?,?,?,?,?,?,?)", br_rows)
    con.executemany(
        """UPDATE fact_alert SET final_severity=?, severity_rationale=?, verdict=?, confidence=?, action=?,
                       triaged_at=?, authorised_by=? WHERE alert_id=?""",
        al_rows,
    )
    con.execute("DROP VIEW IF EXISTS v_incident_queue")
    con.execute("""CREATE VIEW v_incident_queue AS
        SELECT incident_id, status, final_severity, title, alert_count, tactics_covered, max_kill_chain_stage,
               primary_user_key, primary_hostname, first_seen, last_seen, escalation_reasons, authorised_by,
               severity_rationale, related_incident_id,
               CASE final_severity WHEN 'critical' THEN '15 min' WHEN 'high' THEN '30 min' WHEN 'medium' THEN '4 h'
                    WHEN 'low' THEN '24 h' ELSE 'daily batch' END AS sla_triage,
               CASE final_severity WHEN 'critical' THEN datetime(first_seen, '+15 minutes')
                    WHEN 'high' THEN datetime(first_seen, '+30 minutes') WHEN 'medium' THEN datetime(first_seen, '+4 hours')
                    WHEN 'low' THEN datetime(first_seen, '+24 hours') END AS sla_due_utc
        FROM fact_incident
        ORDER BY CASE status WHEN 'escalate_n2' THEN 0 WHEN 'priority_triage' THEN 1 WHEN 'pending_triage' THEN 2
                             WHEN 'batch_review' THEN 3 ELSE 4 END,
                 CASE final_severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                 first_seen""")
    con.commit()
    st = q("SELECT status, COUNT(*), SUM(alert_count) FROM fact_incident GROUP BY 1")
    print("alerts:", len(A), "| incidents:", len(inc_rows), "| reduction:", f"{1-len(inc_rows)/len(A):.1%}")
    for r in st:
        print(f"  {r[0]:16s} incidents={r[1]:5d} alerts={r[2]}")
    print("BTP alerts:", len(btp), "| duplicates:", len(dup))


if __name__ == "__main__":
    main()
