"""
Tarvia SOC - loads the dataset into SQLite and converts it to the hybrid schema (migrate_hybrid.py).

Usage:  python build_db.py --data ../docs --out tarvia_soc.sqlite [--mitre enterprise-attack.json]
Tables:
  L1  fact_alert, bridge_alert_entity, bridge_alert_event
  L2  bridge_alert_incident, fact_incident            (empty: filled by the correlation stage)
  L3  fact_attack_step                                (empty: filled by the investigation stage)
  DIM dim_rule, dim_user, dim_vulnerability, dim_context, dim_log, dim_mitre
  REF ref_severity_matrix
"""

import argparse
import csv
import hashlib
import json
import pathlib
import re
import sqlite3
import time
import urllib.request

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

DDL = r"""
PRAGMA foreign_keys = ON;

-- ============ DIMENSIONS ============
CREATE TABLE dim_mitre (
  technique_id        TEXT PRIMARY KEY,          -- T1566.002
  technique           TEXT NOT NULL,
  is_subtechnique     INTEGER NOT NULL DEFAULT 0,
  parent_technique_id TEXT,
  tactic              TEXT,                      -- primary tactic (earliest kill-chain stage)
  tactic_id           TEXT,                      -- TA0001
  tactics_all         TEXT,                      -- all tactics, comma-separated
  kill_chain_order    INTEGER,                   -- 1 (Reconnaissance) .. 14 (Impact)
  data_sources        TEXT,                      -- which telemetry detects it
  mitigations         TEXT,                      -- Mxxxx: name ; ...
  url                 TEXT,
  in_dataset          INTEGER NOT NULL DEFAULT 0, -- referenced by alerts / rules / sandbox
  framework           TEXT,                       -- enterprise / ics / atlas
  revoked_by          TEXT                        -- successor id when revoked in ATT&CK
);

CREATE TABLE dim_rule (
  rule_id         TEXT PRIMARY KEY,
  nombre          TEXT NOT NULL,
  fuente          TEXT,
  severidad_base  TEXT,                          -- matrix row
  tactica         TEXT,
  tecnica_id      TEXT REFERENCES dim_mitre(technique_id),
  tecnica         TEXT,
  runbook         TEXT,
  logica          TEXT,
  runbook_checks  TEXT,                          -- "Comprobaciones" section of the runbook
  runbook_decision TEXT                          -- "Decisión" section of the runbook
);

CREATE TABLE dim_user (
  user_key        TEXT PRIMARY KEY,              -- lower(username)
  user_id         TEXT UNIQUE,
  username        TEXT,
  upn             TEXT UNIQUE,
  display_name    TEXT,
  department      TEXT,
  title           TEXT,
  location        TEXT,
  manager_upn     TEXT,
  account_type    TEXT,                          -- user / service / admin / external
  privileged      INTEGER,
  vip             INTEGER,
  mfa_method      TEXT,
  status          TEXT,
  workstation     TEXT,
  notes           TEXT,
  hr_event        TEXT,                          -- eventos_rrhh.tipo
  hr_event_date   TEXT,
  hr_fecha_efectiva TEXT,
  hr_detalle      TEXT
);

CREATE TABLE dim_vulnerability (                 -- grain: one asset (hostname); vulns aggregated
  hostname          TEXT PRIMARY KEY,
  asset_id          TEXT,
  ip                TEXT,
  type              TEXT,
  os                TEXT,
  criticality       TEXT,                        -- Baja / Media / Alta / Crítica (matrix column)
  criticality_level INTEGER,                     -- 1..4
  zone              TEXT,
  location          TEXT,
  business_service  TEXT,
  service_criticidad TEXT,
  service_responsable TEXT,
  owner_upn         TEXT,
  internet_facing   INTEGER,
  edr_installed     INTEGER,
  description       TEXT,
  open_vuln_count   INTEGER NOT NULL DEFAULT 0,
  max_cvss_open     REAL,
  cve_ids           TEXT,                        -- id:producto:cvss:estado ; ...
  vuln_notes        TEXT
);

CREATE TABLE dim_context (                       -- context + intelligence
  context_key     TEXT PRIMARY KEY,              -- indicator value, sha256 or change id
  context_type    TEXT NOT NULL,                 -- ip / domain / url / sha256 / change
  reputation      TEXT,                          -- TIP; NULL = unknown (unknown != clean)
  confidence      INTEGER,
  malware_family  TEXT,
  tags            TEXT,
  first_seen      TEXT,
  last_seen       TEXT,
  ti_source       TEXT,
  ti_note         TEXT,
  country         TEXT,                          -- GeoIP
  city            TEXT,
  asn             TEXT,
  as_org          TEXT,
  is_tor          INTEGER,
  is_vpn_provider INTEGER,
  is_hosting      INTEGER,
  is_residential_proxy INTEGER,
  sandbox_file_name TEXT,                        -- sandbox
  sandbox_verdict TEXT,
  sandbox_score   INTEGER,
  sandbox_family  TEXT,
  sandbox_mitre   TEXT,                          -- comma-separated technique ids -> dim_mitre
  sandbox_behaviors TEXT,
  sandbox_network TEXT,
  change_title    TEXT,                          -- approved change window
  change_start    TEXT,
  change_end      TEXT,
  change_requester TEXT,
  change_detail   TEXT,
  change_scope    TEXT
);

CREATE TABLE dim_log (                           -- unified view over the 18 log sources
  event_id    TEXT PRIMARY KEY,                  -- prefix = source
  source      TEXT NOT NULL,
  timestamp   TEXT NOT NULL,                     -- UTC ISO-8601
  user_key    TEXT,                              -- normalised employee identity (may not exist in dim_user)
  customer_id TEXT,
  hostname    TEXT,
  src_ip      TEXT,
  dst         TEXT,                              -- IP, domain, URL, app, bucket...
  action      TEXT,
  result      TEXT,
  sha256      TEXT,
  ref_id      TEXT,                              -- message_id / session_id / build_id
  detail      TEXT NOT NULL                      -- raw record (JSON, untrusted)
);

-- ============ L1: ALERT FACT ============
CREATE TABLE fact_alert (
  alert_id        TEXT PRIMARY KEY,
  created_at      TEXT NOT NULL,
  rule_id         TEXT REFERENCES dim_rule(rule_id),
  technique_id    TEXT REFERENCES dim_mitre(technique_id),
  user_key        TEXT REFERENCES dim_user(user_key),          -- primary entity
  hostname        TEXT REFERENCES dim_vulnerability(hostname), -- primary entity
  context_key     TEXT REFERENCES dim_context(context_key),    -- primary IOC known to the TIP
  event_id        TEXT REFERENCES dim_log(event_id),           -- first related event
  source_product  TEXT,
  rule_name       TEXT,
  rule_severity   TEXT,
  status          TEXT,
  mitre_tactic    TEXT,
  description     TEXT,
  runbook         TEXT,
  entities        TEXT,                          -- JSON
  evidence        TEXT,                          -- JSON, attacker-controllable
  dedup_hash      TEXT,                          -- rule + entities + day
  -- outputs (written by the triage system)
  verdict         TEXT CHECK (verdict IN ('true_positive','benign_true_positive','false_positive','needs_more_info')),
  final_severity  TEXT CHECK (final_severity IN ('informational','low','medium','high','critical')),
  severity_rationale TEXT,
  confidence      REAL CHECK (confidence BETWEEN 0 AND 1),
  action          TEXT,
  triaged_at      TEXT,
  authorised_by   TEXT                           -- change / flow / HR event that authorises it
);

CREATE TABLE bridge_alert_entity (               -- N:M alert <-> entities
  alert_id     TEXT NOT NULL REFERENCES fact_alert(alert_id),
  entity_type  TEXT NOT NULL,                    -- user/host/ip/domain/url/file/customer/cloud_identity/process/ai_session
  entity_value TEXT NOT NULL,
  user_key     TEXT,                             -- resolved -> dim_user
  hostname     TEXT,                             -- resolved -> dim_vulnerability
  context_key  TEXT,                             -- resolved -> dim_context
  PRIMARY KEY (alert_id, entity_type, entity_value)
);

CREATE TABLE bridge_alert_event (                -- N:M alert <-> related_events
  alert_id   TEXT NOT NULL REFERENCES fact_alert(alert_id),
  event_id   TEXT NOT NULL,                      -- -> dim_log (not enforced: a few may be missing)
  in_dim_log INTEGER NOT NULL,
  PRIMARY KEY (alert_id, event_id)
);

-- ============ L2: CORRELATION ============
CREATE TABLE fact_incident (
  incident_id     TEXT PRIMARY KEY,              -- = ticket_id
  title           TEXT,
  first_seen      TEXT,
  last_seen       TEXT,
  alert_count     INTEGER,
  primary_user_key TEXT REFERENCES dim_user(user_key),
  primary_hostname TEXT REFERENCES dim_vulnerability(hostname),
  tactics_covered INTEGER,
  max_kill_chain_stage INTEGER,
  verdict         TEXT,
  final_severity  TEXT,
  severity_rationale TEXT,
  confidence      REAL,
  escalate_n2     INTEGER,
  status          TEXT,
  related_incident_id TEXT REFERENCES fact_incident(incident_id),
  -- L3 investigation report (informe_incidente.schema.json)
  patient_zero    TEXT,
  initial_access  TEXT REFERENCES dim_mitre(technique_id),
  scope           TEXT,                          -- JSON
  root_cause      TEXT,
  containment_plan TEXT,                         -- JSON
  open_questions  TEXT,
  created_at      TEXT,
  updated_at      TEXT,
  escalation_reasons TEXT,                       -- policy s.5 criteria met
  authorised_by   TEXT,                          -- change / flow / HR event id when benign
  triage_stage    TEXT,                          -- L2 / L3
  eradication_and_recovery TEXT,                 -- JSON (L3)
  notifications   TEXT,                          -- JSON (L3)
  detection_gaps  TEXT,                          -- JSON (L3)
  related_incidents TEXT                         -- JSON (L3)
);

CREATE TABLE bridge_alert_incident (
  alert_id      TEXT NOT NULL REFERENCES fact_alert(alert_id),
  incident_id   TEXT NOT NULL REFERENCES fact_incident(incident_id),
  link_reason   TEXT,                            -- shared_user / shared_host / shared_ioc / message_id / session
  link_window   TEXT,                            -- 24h / entity_persistent
  link_score    REAL,
  is_duplicate  INTEGER DEFAULT 0,
  is_authorised INTEGER DEFAULT 0,
  PRIMARY KEY (alert_id, incident_id)
);

-- ============ L3: RECONSTRUCTION ============
CREATE TABLE fact_attack_step (
  step_id         INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id     TEXT NOT NULL REFERENCES fact_incident(incident_id),
  step_order      INTEGER NOT NULL,
  timestamp       TEXT NOT NULL,
  event_id        TEXT REFERENCES dim_log(event_id),
  alert_id        TEXT REFERENCES fact_alert(alert_id),
  technique_id    TEXT REFERENCES dim_mitre(technique_id),
  user_key        TEXT,
  hostname        TEXT,
  context_key     TEXT,
  evidence_origin TEXT CHECK (evidence_origin IN ('alert','hidden_log','context')),
  description     TEXT,
  confidence      REAL
);

-- ============ REFERENCE ============
CREATE TABLE ref_severity_matrix (               -- politica_soc.md section 2
  rule_severity TEXT NOT NULL,
  criticality   TEXT NOT NULL,
  base_severity TEXT NOT NULL,
  PRIMARY KEY (rule_severity, criticality)
);
"""

INDEXES = r"""
CREATE INDEX ix_log_user_ts   ON dim_log(user_key, timestamp);
CREATE INDEX ix_log_host_ts   ON dim_log(hostname, timestamp);
CREATE INDEX ix_log_src_ts    ON dim_log(src_ip, timestamp);
CREATE INDEX ix_log_dst       ON dim_log(dst);
CREATE INDEX ix_log_sha       ON dim_log(sha256);
CREATE INDEX ix_log_ref       ON dim_log(ref_id);
CREATE INDEX ix_log_cust_ts   ON dim_log(customer_id, timestamp);
CREATE INDEX ix_log_source_ts ON dim_log(source, timestamp);
CREATE INDEX ix_alert_ts      ON fact_alert(created_at);
CREATE INDEX ix_alert_rule    ON fact_alert(rule_id);
CREATE INDEX ix_alert_user    ON fact_alert(user_key);
CREATE INDEX ix_alert_host    ON fact_alert(hostname);
CREATE INDEX ix_alert_dedup   ON fact_alert(dedup_hash);
CREATE INDEX ix_bae_value     ON bridge_alert_entity(entity_value);
CREATE INDEX ix_bae_user      ON bridge_alert_entity(user_key);
CREATE INDEX ix_bae_host      ON bridge_alert_entity(hostname);
CREATE INDEX ix_bae_ctx       ON bridge_alert_entity(context_key);
CREATE INDEX ix_baev_event    ON bridge_alert_event(event_id);
CREATE INDEX ix_bai_incident  ON bridge_alert_incident(incident_id);
CREATE INDEX ix_step_incident ON fact_attack_step(incident_id, step_order);
"""

VIEWS = r"""
-- Alert enriched with every dimension + base severity from the policy matrix
CREATE VIEW v_alert_enriched AS
SELECT a.alert_id, a.created_at, a.source_product, a.rule_id, r.nombre AS rule_name, a.rule_severity,
       a.technique_id, m.technique, m.tactic, m.kill_chain_order,
       a.user_key, u.display_name, u.department, u.account_type, u.privileged, u.vip, u.hr_event,
       a.hostname, v.criticality AS asset_criticality, v.business_service, v.zone, v.open_vuln_count, v.max_cvss_open,
       a.context_key, c.reputation, c.malware_family, c.sandbox_verdict,
       (SELECT MAX(x.criticality_level) FROM bridge_alert_entity b JOIN dim_vulnerability x ON x.hostname=b.hostname
         WHERE b.alert_id=a.alert_id) AS max_asset_level,
       s.base_severity AS matrix_base_severity,
       a.runbook, r.runbook_checks, a.dedup_hash, a.verdict, a.final_severity, a.confidence
FROM fact_alert a
LEFT JOIN dim_rule r          ON r.rule_id = a.rule_id
LEFT JOIN dim_mitre m         ON m.technique_id = a.technique_id
LEFT JOIN dim_user u          ON u.user_key = a.user_key
LEFT JOIN dim_vulnerability v ON v.hostname = a.hostname
LEFT JOIN dim_context c       ON c.context_key = a.context_key
LEFT JOIN ref_severity_matrix s ON s.rule_severity = a.rule_severity
     AND s.criticality = COALESCE(v.criticality, CASE WHEN u.vip=1 OR u.privileged=1 THEN 'Alta' ELSE 'Media' END);

-- Approved changes whose window contains the alert time (candidate benign_true_positive).
-- entity_match = an alert entity, host or process appears in the change text; long windows (recurring flows) need it.
CREATE VIEW v_alert_change_overlap AS
SELECT a.alert_id, c.context_key AS change_id, c.change_title, c.change_scope, c.change_detail,
       ROUND((julianday(c.change_end) - julianday(c.change_start)) * 24, 1) AS window_hours,
       EXISTS (SELECT 1 FROM bridge_alert_entity b
               WHERE b.alert_id = a.alert_id AND length(b.entity_value) > 3
                 AND (instr(lower(c.change_detail), lower(b.entity_value)) > 0
                   OR instr(lower(c.change_scope),  lower(b.entity_value)) > 0
                   OR instr(lower(c.change_title),  lower(b.entity_value)) > 0)) AS entity_match
FROM fact_alert a
JOIN dim_context c ON c.context_type = 'change'
 AND replace(substr(a.created_at,1,16),'T',' ') BETWEEN c.change_start AND c.change_end;

-- Duplicate groups (same rule + entities + day)
CREATE VIEW v_alert_duplicates AS
SELECT dedup_hash, COUNT(*) AS n, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen,
       GROUP_CONCAT(alert_id) AS alert_ids
FROM fact_alert GROUP BY dedup_hash HAVING COUNT(*) > 1;

-- Incident timeline (L3) ordered by time and kill chain
CREATE VIEW v_incident_timeline AS
SELECT s.incident_id, s.step_order, s.timestamp, m.kill_chain_order, m.tactic, s.technique_id, m.technique,
       s.evidence_origin, s.description, s.event_id, s.alert_id, s.user_key, s.hostname, s.confidence
FROM fact_attack_step s LEFT JOIN dim_mitre m ON m.technique_id = s.technique_id
ORDER BY s.incident_id, s.step_order;
"""

SEV = ["informational", "low", "medium", "high", "critical"]
CRIT = ["Baja", "Media", "Alta", "Crítica"]
MATRIX = {
    "informational": ["informational", "informational", "low", "low"],
    "low": ["informational", "low", "low", "medium"],
    "medium": ["low", "medium", "medium", "high"],
    "high": ["medium", "high", "high", "critical"],
    "critical": ["high", "critical", "critical", "critical"],
}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def b(v):
    if v is None or v == "":
        return None
    return 1 if str(v).strip().lower() in ("true", "1", "yes", "sí", "si") else 0


def norm_user(v):
    if not v or not isinstance(v, str):
        return None
    v = v.strip().lower()
    if "\\" in v:
        v = v.split("\\")[-1]
    if "@" in v:
        v = v.split("@")[0]
    return v or None


def g(d, path):
    for p in path.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def j(v):
    return json.dumps(v, ensure_ascii=False) if v is not None else None


def jsonl(p):
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def csvr(p):
    with open(p, encoding="utf-8", newline="") as f:
        yield from csv.DictReader(f)


# ---------------------------------------------------------------- MITRE
def load_mitre(con, path, used, ds_names):
    """ds_names: {technique_id: (name, tactic)} from catalog/alerts, used for ICS / ATLAS ids."""
    if path and pathlib.Path(path).exists():
        raw = json.load(open(path, encoding="utf-8"))
    else:
        log("downloading MITRE ATT&CK Enterprise ...")
        with urllib.request.urlopen(MITRE_URL, timeout=120) as r:
            raw = json.loads(r.read().decode("utf-8"))
    objs = raw["objects"]
    byid = {o["id"]: o for o in objs}
    ext = lambda o: next((e for e in o.get("external_references", []) if e.get("source_name") == "mitre-attack"), {})
    tactics = {
        o["x_mitre_shortname"]: (o["name"], ext(o).get("external_id")) for o in objs if o["type"] == "x-mitre-tactic"
    }
    tid2short = {o["id"]: o["x_mitre_shortname"] for o in objs if o["type"] == "x-mitre-tactic"}
    matrix = next(o for o in objs if o["type"] == "x-mitre-matrix")
    order = {tid2short[t]: i + 1 for i, t in enumerate(matrix["tactic_refs"]) if t in tid2short}
    order_by_name = {tactics[k][0]: v for k, v in order.items()}
    mitig, detect, revoked = {}, {}, {}
    for o in objs:
        if o["type"] != "relationship" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        src = byid.get(o["source_ref"])
        tgt = o["target_ref"]
        if not src:
            continue
        rt = o["relationship_type"]
        if rt == "mitigates" and src["type"] == "course-of-action":
            mitig.setdefault(tgt, set()).add(f'{ext(src).get("external_id")}: {src["name"]}')
        elif rt == "detects":
            if src["type"] == "x-mitre-data-component":  # ATT&CK <= v17
                detect.setdefault(tgt, set()).add(src["name"])
            elif src["type"] == "x-mitre-detection-strategy":  # ATT&CK v18+
                for an in src.get("x_mitre_analytic_refs", []):
                    for ls in byid.get(an, {}).get("x_mitre_log_source_references", []):
                        dc = byid.get(ls.get("x_mitre_data_component_ref"))
                        if dc:
                            detect.setdefault(tgt, set()).add(dc["name"])
        elif rt == "revoked-by" and src["type"] == "attack-pattern":
            revoked[src["id"]] = byid.get(tgt)
    rows = {}

    def build(o, tid, name, rev=None):
        phases = sorted(
            [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
            key=lambda p: order.get(p, 99),
        )
        prim = phases[0] if phases else None
        ds = o.get("x_mitre_data_sources") or sorted(detect.get(o["id"], []))
        return [
            tid,
            name,
            1 if "." in tid else 0,
            tid.split(".")[0] if "." in tid else None,
            tactics.get(prim, (None, None))[0],
            tactics.get(prim, (None, None))[1],
            ", ".join(tactics[p][0] for p in phases if p in tactics),
            order.get(prim),
            "; ".join(ds) or None,
            "; ".join(sorted(mitig.get(o["id"], []))) or None,
            ext(o).get("url"),
            1 if tid in used else 0,
            "enterprise",
            rev,
        ]

    for o in objs:
        if o["type"] != "attack-pattern":
            continue
        tid = ext(o).get("external_id")
        if not tid:
            continue
        if o.get("revoked"):
            if tid in used and revoked.get(o["id"]):  # keep ids the dataset uses, attributes from successor
                succ = revoked[o["id"]]
                rows[tid] = build(
                    succ, tid, f'{o["name"]} [revoked -> {ext(succ).get("external_id")}]', ext(succ).get("external_id")
                )
            continue
        if o.get("x_mitre_deprecated") and tid not in used:
            continue
        rows[tid] = build(o, tid, o["name"])
    for t in used:  # ICS (T0xxx) and ATLAS (AML.*) ids
        if t in rows:
            continue
        name, tac = ds_names.get(t, (None, None))
        rows[t] = [
            t,
            name or "(unknown)",
            1 if "." in t else 0,
            t.rsplit(".", 1)[0] if "." in t and not t.startswith("AML") else None,
            tac,
            None,
            tac,
            order_by_name.get(tac),
            None,
            None,
            None,
            1,
            "atlas" if t.startswith("AML") else ("ics" if t.startswith("T0") else "enterprise"),
            None,
        ]
    con.executemany(f"INSERT INTO dim_mitre VALUES ({','.join('?'*14)})", [tuple(r) for r in rows.values()])
    log(
        f"dim_mitre: {len(rows)} techniques | used in dataset: {len(used)} | with data_sources: "
        f"{sum(1 for r in rows.values() if r[8])} | non-enterprise: {[t for t in used if rows[t][12] != 'enterprise']}"
    )


# ---------------------------------------------------------------- RUNBOOKS
def runbook_sections(path):
    txt = path.read_text(encoding="utf-8")
    sec = lambda name: (re.search(rf"## {name}\s*\n(.*?)(?=\n## |\Z)", txt, re.S) or [None, None])[1]
    return (sec("Comprobaciones") or "").strip() or None, (sec("Decisi[oó]n") or "").strip() or None


# ---------------------------------------------------------------- LOG MAPPING
def map_log(src, d):
    """returns (user, customer, host, src_ip, dst, action, result, sha256, ref_id)"""
    if src == "ad_events":
        return (
            d.get("subject"),
            None,
            d.get("src_host") or d.get("dc"),
            None,
            d.get("target"),
            d.get("event"),
            d.get("event_code"),
            None,
            None,
        )
    if src == "ai_gateway":
        return (
            None,
            d.get("customer_id"),
            None,
            d.get("src_ip"),
            (d.get("tool_calls") and j(d["tool_calls"])[:200]) or None,
            g(d, "guardrail.action"),
            g(d, "guardrail.category"),
            None,
            d.get("session_id"),
        )
    if src == "cicd_builds":
        return (
            g(d, "details.author"),
            None,
            d.get("runner"),
            None,
            d.get("pipeline"),
            d.get("step"),
            d.get("status"),
            None,
            d.get("build_id"),
        )
    if src == "cloudtrail":
        return (
            g(d, "userIdentity.userName"),
            None,
            None,
            d.get("sourceIPAddress"),
            g(d, "requestParameters.bucketName") or g(d, "requestParameters.userName"),
            d.get("eventName"),
            d.get("errorCode") or "success",
            None,
            g(d, "userIdentity.accessKeyId"),
        )
    if src == "dlp":
        return (
            d.get("user"),
            None,
            d.get("hostname"),
            None,
            d.get("destination"),
            d.get("action"),
            d.get("policy"),
            None,
            None,
        )
    if src == "ecom_account":
        return (
            None,
            d.get("customer_id"),
            None,
            d.get("src_ip"),
            None,
            d.get("event"),
            None,
            None,
            g(d, "details.order_id"),
        )
    if src == "ecom_auth":
        return (
            None,
            d.get("customer_id"),
            None,
            d.get("src_ip"),
            d.get("email"),
            "login",
            d.get("result"),
            None,
            d.get("device_fp"),
        )
    if src == "edr_events":
        return (
            d.get("user"),
            None,
            d.get("hostname"),
            None,
            d.get("process_name"),
            d.get("event_type"),
            g(d, "details.action") or g(d, "details.detection"),
            d.get("sha256"),
            None,
        )
    if src == "email":
        rc = d.get("recipients") or []
        at = d.get("attachments") or []
        sha = next((a.get("sha256") for a in at if isinstance(a, dict) and a.get("sha256")), None)
        return (
            rc[0] if rc and d.get("direction") != "outbound" else d.get("sender"),
            None,
            None,
            d.get("sender_ip"),
            d.get("sender") if d.get("direction") != "outbound" else (rc[0] if rc else None),
            d.get("action"),
            d.get("verdict"),
            sha,
            d.get("message_id"),
        )
    if src == "email_clicks":
        return (
            d.get("user"),
            None,
            None,
            d.get("src_ip"),
            d.get("url"),
            d.get("action"),
            d.get("verdict_at_click"),
            None,
            d.get("message_id"),
        )
    if src == "idp_audit":
        return (d.get("actor_upn"), None, None, d.get("src_ip"), d.get("target"), d.get("operation"), None, None, None)
    if src == "idp_signins":
        return (
            d.get("user_upn"),
            None,
            d.get("device_id"),
            d.get("src_ip"),
            d.get("app"),
            "signin",
            d.get("result"),
            None,
            d.get("session_id"),
        )
    if src == "sql_audit":
        return (
            d.get("user"),
            None,
            d.get("client_host"),
            None,
            f'{d.get("database")}.{d.get("object")}',
            d.get("statement_type"),
            str(d.get("rows_returned")),
            None,
            None,
        )
    if src == "vpn":
        return (
            d.get("user"),
            None,
            None,
            d.get("src_ip"),
            d.get("assigned_ip"),
            d.get("action"),
            d.get("mfa_result"),
            None,
            None,
        )
    if src == "waf":
        return (None, None, None, d.get("src_ip"), d.get("host"), d.get("action"), d.get("rule_id"), None, None)
    if src == "dns":
        return (
            None,
            None,
            d.get("hostname"),
            d.get("src_ip"),
            d.get("query"),
            d.get("qtype"),
            d.get("rcode"),
            None,
            None,
        )
    if src == "firewall":
        return (
            None,
            None,
            None,
            d.get("src_ip"),
            f'{d.get("dst_ip")}:{d.get("dst_port")}',
            d.get("action"),
            d.get("rule"),
            None,
            None,
        )
    if src == "proxy":
        return (
            d.get("user"),
            None,
            d.get("hostname"),
            d.get("src_ip"),
            d.get("domain"),
            d.get("action"),
            d.get("status"),
            None,
            None,
        )
    raise ValueError(src)


# ---------------------------------------------------------------- ALERT ENTITIES
def alert_entities(e):
    out = []
    for u in e.get("users", []) or []:
        out.append(("user", u.get("upn") if isinstance(u, dict) else u))
    for h in e.get("hosts", []) or []:
        if isinstance(h, dict):
            if h.get("hostname"):
                out.append(("host", h["hostname"]))
            if h.get("ip"):
                out.append(("ip", h["ip"]))
        else:
            out.append(("host", h))
    for k, t in (("ips", "ip"), ("domains", "domain"), ("urls", "url")):
        for v in e.get(k, []) or []:
            out.append((t, v))
    for f in e.get("files", []) or []:
        out.append(("file", f.get("sha256") or f.get("name")))
    for c in e.get("customers", []) or []:
        out.append(("customer", c.get("customer_id") if isinstance(c, dict) else c))
    for p in e.get("processes", []) or []:
        out.append(("process", p.get("name")))
    cl = e.get("cloud")
    if isinstance(cl, dict):
        for k in ("identity", "new_user"):
            if cl.get(k):
                out.append(("cloud_identity", cl[k]))
        if cl.get("bucket"):
            out.append(("bucket", cl["bucket"]))
        if cl.get("access_key"):
            out.append(("access_key", cl["access_key"]))
    if e.get("ai_session"):
        out.append(("ai_session", e["ai_session"]))
    return [(t, str(v)) for t, v in out if v]


# ---------------------------------------------------------------- MAIN
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(pathlib.Path(__file__).resolve().parent.parent / "docs"))
    ap.add_argument("--out", default="tarvia_soc.sqlite")
    ap.add_argument("--mitre", default=None, help="local enterprise-attack.json (else downloaded)")
    ap.add_argument("--no-hybrid", action="store_true", help="stop after the star load (no hybrid conversion)")
    a = ap.parse_args()
    D = pathlib.Path(a.data)
    out = pathlib.Path(a.out)
    if out.exists():
        out.unlink()
    con = sqlite3.connect(out)
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")
    con.executescript(DDL)

    # ---- reference matrix
    con.executemany(
        "INSERT INTO ref_severity_matrix VALUES (?,?,?)", [(s, CRIT[i], MATRIX[s][i]) for s in MATRIX for i in range(4)]
    )

    # ---- alerts first pass: collect technique ids
    alerts = list(jsonl(D / "03_alertas/alertas.jsonl"))
    catalog = list(csvr(D / "01_contexto/catalogo_casos_de_uso.csv"))
    sandbox = list(jsonl(D / "05_inteligencia/sandbox_informes.jsonl"))
    used = {x["mitre"]["technique_id"] for x in alerts if x.get("mitre")} | {r["tecnica_id"] for r in catalog}
    for s in sandbox:
        used |= set(s.get("mitre") or [])
    used.discard(None)
    used.discard("")
    ds_names = {r["tecnica_id"]: (r["tecnica"], r["tactica"]) for r in catalog}
    for x in alerts:
        m = x.get("mitre") or {}
        ds_names.setdefault(m.get("technique_id"), (m.get("technique"), m.get("tactic")))
    load_mitre(con, a.mitre, used, ds_names)

    # ---- dim_rule
    rb = {p.stem: runbook_sections(p) for p in (D / "01_contexto/runbooks").glob("RB-*.md")}
    con.executemany(
        "INSERT INTO dim_rule VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [
            (
                r["rule_id"],
                r["nombre"],
                r["fuente"],
                r["severidad_base"],
                r["tactica"],
                r["tecnica_id"],
                r["tecnica"],
                r["runbook"],
                r["logica"],
                *rb.get(r["runbook"], (None, None)),
            )
            for r in catalog
        ],
    )
    known_rules = {r["rule_id"] for r in catalog}
    log("dim_rule:", len(catalog))

    # ---- dim_user
    hr = {}
    for r in csvr(D / "02_inventario/eventos_rrhh.csv"):
        k = norm_user(r["usuario"])
        if k not in hr or r["fecha"] > hr[k]["fecha"]:
            hr[k] = r
    users = list(csvr(D / "02_inventario/usuarios.csv"))
    con.executemany(
        "INSERT INTO dim_user VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            (
                norm_user(u["username"]),
                u["user_id"],
                u["username"],
                u["upn"].lower(),
                u["display_name"],
                u["department"],
                u["title"],
                u["location"],
                u["manager_upn"] or None,
                u["account_type"],
                b(u["privileged"]),
                b(u["vip"]),
                u["mfa_method"],
                u["status"],
                u["workstation"] or None,
                u["notes"] or None,
                *(
                    (hr[k]["tipo"], hr[k]["fecha"], hr[k]["fecha_efectiva"], hr[k]["detalle"])
                    if (k := norm_user(u["username"])) in hr
                    else (None,) * 4
                ),
            )
            for u in users
        ],
    )
    user_keys = {norm_user(u["username"]) for u in users}
    log("dim_user:", len(users), "| HR events attached:", sum(1 for k in hr if k in user_keys))

    # ---- dim_vulnerability (asset grain)
    svcs = list(csvr(D / "02_inventario/servicios_negocio.csv"))

    def svc_of(name):
        for s in svcs:
            if name and (name == s["servicio"] or name.startswith(s["servicio"])):
                return s
        return None

    vul = {}
    for v in csvr(D / "02_inventario/vulnerabilidades.csv"):
        vul.setdefault(v["hostname"], []).append(v)
    rows = []
    for x in csvr(D / "02_inventario/activos.csv"):
        vs = vul.get(x["hostname"], [])
        s = svc_of(x["business_service"])
        opn = [v for v in vs if v["estado"] == "abierta"]
        cv = lambda v: (float(m.group()) if (m := re.search(r"\d+(\.\d+)?", v["severidad_cvss"] or "")) else None)
        rows.append(
            (
                x["hostname"],
                x["asset_id"],
                x["ip"],
                x["type"],
                x["os"],
                x["criticality"],
                CRIT.index(x["criticality"]) + 1 if x["criticality"] in CRIT else None,
                x["zone"],
                x["location"],
                x["business_service"],
                s["criticidad"] if s else None,
                s["responsable"] if s else None,
                x["owner_upn"] or None,
                b(x["internet_facing"]),
                b(x["edr_installed"]),
                x["description"] or None,
                len(opn),
                max([cv(v) for v in opn if cv(v) is not None], default=None),
                " ; ".join(f'{v["id"]}:{v["producto"]}:{v["severidad_cvss"]}:{v["estado"]}' for v in vs) or None,
                " ; ".join(v["notas"] for v in vs if v["notas"]) or None,
            )
        )
    con.executemany(f"INSERT INTO dim_vulnerability VALUES ({','.join('?'*20)})", rows)
    hosts = {r[0] for r in rows}
    log("dim_vulnerability:", len(rows), "assets |", sum(len(v) for v in vul.values()), "vulnerabilities aggregated")

    # ---- dim_context (TIP + GeoIP + sandbox + changes, merged by value)
    ctx = {}

    def C(key, typ):
        if key not in ctx:
            ctx[key] = {"context_key": key, "context_type": typ}
        return ctx[key]

    for t in jsonl(D / "05_inteligencia/ti_feed.jsonl"):
        c = C(t["value"], t["indicator_type"])
        c.update(
            reputation=t.get("reputation"),
            confidence=t.get("confidence"),
            malware_family=t.get("malware_family") or None,
            tags=t.get("tags") or None,
            first_seen=t.get("first_seen"),
            last_seen=t.get("last_seen"),
            ti_source=t.get("source"),
            ti_note=t.get("note") or None,
        )
    for r in csvr(D / "05_inteligencia/geoip_asn.csv"):
        c = C(r["ip"], "ip")
        c.update(
            country=r["country"],
            city=r["city"],
            asn=r["asn"],
            as_org=r["as_org"],
            is_tor=b(r["is_tor"]),
            is_vpn_provider=b(r["is_vpn_provider"]),
            is_hosting=b(r["is_hosting"]),
            is_residential_proxy=b(r["is_residential_proxy"]),
        )
    for s in sandbox:
        c = C(s["sha256"], "sha256")
        c.update(
            sandbox_file_name=s.get("file_name"),
            sandbox_verdict=s.get("verdict"),
            sandbox_score=s.get("score"),
            sandbox_family=s.get("malware_family"),
            sandbox_mitre=",".join(s.get("mitre") or []) or None,
            sandbox_behaviors=j(s.get("behaviors")),
            sandbox_network=j(s.get("network")),
        )
    for r in csvr(D / "02_inventario/calendario_cambios.csv"):
        c = C(r["id"], "change")
        c.update(
            change_title=r["titulo"],
            change_start=r["inicio"],
            change_end=r["fin"],
            change_requester=r["solicitante"],
            change_detail=r["detalle"],
            change_scope=r["alcance"],
        )
    cols = [r[1] for r in con.execute("PRAGMA table_info(dim_context)")]
    con.executemany(
        f"INSERT INTO dim_context VALUES ({','.join('?'*len(cols))})",
        [tuple(c.get(k) for k in cols) for c in ctx.values()],
    )
    log("dim_context:", len(ctx), "rows")

    # ---- dim_log
    n_total = 0
    for p in sorted(list((D / "04_logs").glob("*.jsonl")) + list((D / "04_logs").glob("*.csv"))):
        src = p.stem
        it = jsonl(p) if p.suffix == ".jsonl" else csvr(p)
        batch, n = [], 0
        for d in it:
            u, cu, h, sip, dst, act, res, sha, ref = map_log(src, d)
            batch.append(
                (
                    d["event_id"],
                    src,
                    d["timestamp"],
                    norm_user(u),
                    cu,
                    h,
                    sip,
                    None if dst is None else str(dst),
                    act,
                    None if res is None else str(res),
                    sha,
                    ref,
                    json.dumps(d, ensure_ascii=False),
                )
            )
            if len(batch) >= 20000:
                con.executemany("INSERT INTO dim_log VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
                n += len(batch)
                batch = []
        con.executemany("INSERT INTO dim_log VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
        n += len(batch)
        con.commit()
        n_total += n
        log(f"dim_log <- {src}: {n}")
    log("dim_log total:", n_total)

    # ---- fact_alert + bridges
    fa, be, bv = [], [], []
    for x in alerts:
        ents = alert_entities(x.get("entities") or {})
        res = []
        for t, v in ents:
            uk = norm_user(v) if t == "user" else None
            hn = v if t == "host" and v in hosts else None
            ck = v if t in ("ip", "domain", "url", "file") and v in ctx else None
            res.append((x["alert_id"], t, v, uk if uk in user_keys else None, hn, ck))
        seen = set()
        for r in res:
            if (r[1], r[2]) not in seen:
                seen.add((r[1], r[2]))
                be.append(r)
        p_user = next((r[3] for r in res if r[3]), None)
        p_host = next((r[4] for r in res if r[4]), None)
        prio = {"file": 0, "domain": 1, "url": 2, "ip": 3}
        p_ctx = next((r[5] for r in sorted(res, key=lambda r: prio.get(r[1], 9)) if r[5]), None)
        rel = list(dict.fromkeys(x.get("related_events") or []))
        for ev in rel:
            bv.append((x["alert_id"], ev))
        dk = hashlib.sha1(
            (x["rule_id"] + "|" + "|".join(sorted(f"{t}:{v}" for t, v in seen)) + "|" + x["created_at"][:10]).encode()
        ).hexdigest()[:16]
        m = x.get("mitre") or {}
        fa.append(
            (
                x["alert_id"],
                x["created_at"],
                x["rule_id"] if x["rule_id"] in known_rules else None,
                m.get("technique_id"),
                p_user,
                p_host,
                p_ctx,
                rel[0] if rel else None,
                x.get("source_product"),
                x.get("rule_name"),
                x.get("severity"),
                x.get("status"),
                m.get("tactic"),
                x.get("description"),
                x.get("runbook"),
                j(x.get("entities")),
                j(x.get("evidence")),
                dk,
            )
        )
    # first related event must exist in dim_log for the FK
    con.execute("CREATE TEMP TABLE _ev(event_id TEXT PRIMARY KEY)")
    con.executemany("INSERT OR IGNORE INTO _ev VALUES (?)", [(e,) for _, e in bv])
    present = {r[0] for r in con.execute("SELECT e.event_id FROM _ev e JOIN dim_log l ON l.event_id=e.event_id")}
    fa = [r[:7] + ((r[7] if r[7] in present else None),) + r[8:] for r in fa]
    con.executemany(
        f"INSERT INTO fact_alert(alert_id,created_at,rule_id,technique_id,user_key,hostname,context_key,event_id,"
        f"source_product,rule_name,rule_severity,status,mitre_tactic,description,runbook,entities,evidence,dedup_hash) "
        f"VALUES ({','.join('?'*18)})",
        fa,
    )
    con.executemany("INSERT INTO bridge_alert_entity VALUES (?,?,?,?,?,?)", be)
    con.executemany(
        "INSERT INTO bridge_alert_event VALUES (?,?,?)", [(al, ev, 1 if ev in present else 0) for al, ev in bv]
    )
    con.commit()
    log(
        f"fact_alert: {len(fa)} | bridge_alert_entity: {len(be)} | bridge_alert_event: {len(bv)} ({len(bv)-sum(1 for _,e in bv if e in present)} missing in logs)"
    )

    log("indexes + views ...")
    con.executescript(INDEXES)
    con.executescript(VIEWS)
    con.execute("ANALYZE")
    con.commit()
    bad = con.execute("PRAGMA foreign_key_check").fetchall()
    log("foreign_key_check violations:", len(bad), bad[:5])
    con.execute("VACUUM")
    con.close()
    log("star load done ->", out, f"{out.stat().st_size/1e6:.0f} MB")
    if not a.no_hybrid:  # convert to the hybrid schema (single main database)
        import subprocess
        import sys

        subprocess.run(
            [
                sys.executable,
                str(pathlib.Path(__file__).with_name("migrate_hybrid.py")),
                "--db",
                str(out),
                "--data",
                str(D),
            ],
            check=True,
        )


if __name__ == "__main__":
    main()
