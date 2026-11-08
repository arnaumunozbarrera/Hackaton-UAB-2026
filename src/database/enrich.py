"""Derived layer over the agreed schema: pipeline tables, LLM catalogue views and materialised lookups.

Why: the read-only query catalogue of the prompt (`prompt_builder.schema.QUERIES`) is written against logical
names (`dim_log`, `fact_alert`, `v_alert_enriched`...). This module creates exactly those names over the real
tables, so the catalogue, the prompt and its tests stay unchanged. Lookups that need Python logic (identity
normalisation, the severity matrix, the most critical affected asset) are materialised; the rest are views.
Every step is idempotent and incremental: run it after `build` and after each API sync.

    python -m src.database.enrich [--db data/tarvia.sqlite] [--rebuild]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from collections import defaultdict
from pathlib import Path

from .schema import ROOT

PIPELINE_SQL = Path(__file__).with_name("pipeline.sql")
DEFAULT_DB = ROOT / "data" / "tarvia.sqlite"
CRITICALITY_RANK = {"Crítica": 4, "Alta": 3, "Media": 2, "Baja": 1}
OT_MARKERS = ("PLC-", "HMI-", "SCADA", "OT-")


def db_path(path: str | Path | None = None) -> Path:
    """Explicit path, else TARVIA_DB, else data/tarvia.sqlite. A stale TARVIA_DB falls back to the default."""
    if path:
        return Path(path)
    configured = os.environ.get("TARVIA_DB")
    if configured and not Path(configured).exists() and DEFAULT_DB.exists():
        print(f"[db] TARVIA_DB={configured} does not exist; using {DEFAULT_DB}")
        return DEFAULT_DB
    return Path(configured or DEFAULT_DB)


def normalise_identity(value: object) -> str | None:
    """Same rule as log_noise_discard.templates.normalise_identity: lower case, no domain prefix or UPN suffix."""
    if value in (None, ""):
        return None
    return str(value).lower().split("\\")[-1].split("@")[0]


# ---------------------------------------------------------------------------------------------- dim_log
# One SELECT per source projecting onto the dim_log columns. user_raw is normalised in Python.
_U = "LEFT JOIN users u ON u.user_id = t.user_id"
_A = "LEFT JOIN assets a ON a.asset_id = t.asset_id"
LOG_SELECTS: dict[str, str] = {
    "vpn_logs": f"SELECT t.event_id, u.username, NULL, NULL, t.src_ip, NULL, t.action, t.mfa_result, NULL, NULL "
    f"FROM vpn_logs t {_U}",
    "idp_signins_logs": f"SELECT t.event_id, u.username, NULL, NULL, t.src_ip, t.app, 'signin', t.result, NULL, "
    f"t.session_id FROM idp_signins_logs t {_U}",
    "idp_audit_logs": "SELECT t.event_id, u.username, NULL, NULL, t.src_ip, t.target_resource, t.operation, NULL, "
    "NULL, NULL FROM idp_audit_logs t LEFT JOIN users u ON u.user_id = t.actor_user_id",
    "ad_events_logs": "SELECT t.event_id, COALESCE(su.username, t.subject_unresolved), NULL, "
    "COALESCE(sa.hostname, dc.hostname), NULL, COALESCE(tu.username, t.target_unresolved), t.event_code, NULL, NULL, "
    "NULL FROM ad_events_logs t LEFT JOIN users su ON su.user_id = t.subject_user_id "
    "LEFT JOIN users tu ON tu.user_id = t.target_user_id LEFT JOIN assets sa ON sa.asset_id = t.source_asset_id "
    "LEFT JOIN assets dc ON dc.asset_id = t.dc_asset_id",
    "edr_logs": f"SELECT t.event_id, COALESCE(u.username, t.unresolved_user), NULL, a.hostname, a.ip, "
    f"t.process_name, t.event_type, NULL, t.sha256, NULL FROM edr_logs t {_U} {_A}",
    "proxy_logs": f"SELECT t.event_id, COALESCE(u.username, t.unresolved_user), NULL, a.hostname, t.src_ip, "
    f"t.domain, t.action, t.http_status, NULL, NULL FROM proxy_logs t {_U} {_A}",
    "dns_logs": f"SELECT t.event_id, NULL, NULL, a.hostname, t.src_ip, t.query, t.qtype, t.rcode, NULL, NULL "
    f"FROM dns_logs t {_A}",
    "firewall_logs": "SELECT t.event_id, NULL, NULL, a.hostname, t.src_ip, t.dst_ip, t.action, NULL, NULL, NULL "
    "FROM firewall_logs t LEFT JOIN assets a ON a.ip = t.src_ip",
    "email_logs": "SELECT t.event_id, COALESCE(ru.username, r.recipient_unresolved), NULL, NULL, t.sender_ip, "
    "COALESCE(su.username, t.sender_unresolved), t.action, t.verdict, "
    "(SELECT sha256 FROM email_attachments x WHERE x.event_id = t.event_id ORDER BY position LIMIT 1), "
    "t.message_id FROM email_logs t LEFT JOIN email_recipients r ON r.event_id = t.event_id AND r.position = 0 "
    "LEFT JOIN users ru ON ru.user_id = r.recipient_user_id LEFT JOIN users su ON su.user_id = t.sender_user_id",
    "email_clicks_logs": f"SELECT t.event_id, u.username, NULL, NULL, t.src_ip, t.url, t.action, t.verdict_at_click, "
    f"NULL, e.message_id FROM email_clicks_logs t {_U} LEFT JOIN email_logs e ON e.event_id = t.email_event_id",
    "dlp_logs": f"SELECT t.event_id, u.username, NULL, a.hostname, a.ip, t.destination, t.action, t.policy, NULL, "
    f"NULL FROM dlp_logs t {_U} {_A}",
    "sql_audit_logs": f"SELECT t.event_id, u.username, NULL, a.hostname, a.ip, t.database || '.' || "
    f"COALESCE(t.object, ''), t.statement_type, t.rows_returned, NULL, NULL FROM sql_audit_logs t {_U} "
    f"LEFT JOIN assets a ON a.asset_id = t.client_asset_id",
    "waf_logs": "SELECT t.event_id, NULL, NULL, NULL, t.src_ip, t.host, t.action, t.http_status, NULL, NULL "
    "FROM waf_logs t",
    "ecom_auth_logs": "SELECT t.event_id, NULL, t.customer_id, NULL, t.src_ip, NULL, 'login', t.result, NULL, "
    "t.device_fp FROM ecom_auth_logs t",
    "ecom_account_logs": "SELECT t.event_id, NULL, t.customer_id, NULL, t.src_ip, NULL, t.event_type, NULL, NULL, "
    "NULL FROM ecom_account_logs t",
    "ai_gateway_logs": "SELECT t.event_id, NULL, t.customer_id, NULL, t.src_ip, t.model, t.guardrail_action, "
    "t.guardrail_category, NULL, t.session_id FROM ai_gateway_logs t",
    "cloudtrail_logs": "SELECT t.event_id, t.identity_name, NULL, NULL, t.src_ip, t.event_name, t.event_name, "
    "t.error_code, NULL, t.access_key_id FROM cloudtrail_logs t",
    "cicd_builds_logs": "SELECT t.event_id, NULL, NULL, a.hostname, a.ip, t.pipeline, t.step, t.status, NULL, "
    "t.build_id FROM cicd_builds_logs t LEFT JOIN assets a ON a.asset_id = t.runner_asset_id",
}
DIM_LOG_COLUMNS = (
    "event_id", "source", "timestamp", "user_key", "customer_id", "hostname", "src_ip", "dst", "action", "result",
    "sha256", "ref_id",
)  # fmt: skip


def _create_dim_log(conn: sqlite3.Connection) -> int:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS dim_log (event_id TEXT PRIMARY KEY, source TEXT NOT NULL, timestamp TEXT NOT NULL, "
        "user_key TEXT, customer_id TEXT, hostname TEXT, src_ip TEXT, dst TEXT, action TEXT, result TEXT, "
        "sha256 TEXT, ref_id TEXT)"
    )
    added = 0
    for table, select in LOG_SELECTS.items():
        sql = (
            select.replace("SELECT ", "SELECT l.source, l.timestamp, ", 1).replace(
                f"FROM {table} t", f"FROM {table} t JOIN logs l ON l.event_id = t.event_id", 1
            )
            + " WHERE NOT EXISTS (SELECT 1 FROM dim_log d WHERE d.event_id = t.event_id)"
        )
        rows = []
        for source, ts, eid, user, customer, host, ip, dst, action, result, sha, ref in conn.execute(sql):
            rows.append((eid, source, ts, normalise_identity(user), customer, host, ip,
                         None if dst is None else str(dst), action,
                         None if result is None else str(result), sha, ref))  # fmt: skip
        conn.executemany(f"INSERT INTO dim_log VALUES ({','.join('?' * len(DIM_LOG_COLUMNS))})", rows)
        added += len(rows)
    for column in ("user_key", "hostname", "src_ip", "dst", "customer_id", "ref_id", "sha256"):
        conn.execute(f"CREATE INDEX IF NOT EXISTS idx_dim_log_{column} ON dim_log ({column}, timestamp)")
    return added


def _create_log_detail_view(conn: sqlite3.Connection) -> None:
    """v_log_detail: the full stored row of any log as JSON (attacker-controllable content)."""
    legs = []
    for table in LOG_SELECTS:
        cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")') if r[1] != "event_id"]
        pairs = ", ".join(f"'{c}', t.\"{c}\"" for c in cols)
        legs.append(
            f"SELECT l.event_id, l.source, l.timestamp, json_object({pairs}) AS detail "
            f'FROM logs l JOIN "{table}" t ON t.event_id = l.event_id'
        )
    conn.execute("DROP VIEW IF EXISTS v_log_detail")
    conn.execute("CREATE VIEW v_log_detail AS " + " UNION ALL ".join(legs))


# ---------------------------------------------------------------------------------------------- views
VIEWS: dict[str, str] = {
    "dim_user": """
        SELECT u.user_id, lower(u.username) AS user_key, u.upn, u.display_name, u.account_type, u.department,
               u.title, u.privileged, u.vip, u.status, w.hostname AS workstation,
               h.event_type AS hr_event, h.effective_date AS hr_fecha_efectiva, h.details AS hr_detalle
        FROM users u
        LEFT JOIN assets w ON w.asset_id = u.workstation_asset_id
        LEFT JOIN hr_events h ON h.hr_event_id = (
            SELECT hr_event_id FROM hr_events x WHERE x.user_id = u.user_id
            ORDER BY x.recorded_date DESC, x.hr_event_id DESC LIMIT 1)""",
    "dim_vulnerability": """
        SELECT a.asset_id, a.hostname, a.type, a.criticality, a.zone_id AS zone, a.business_service,
               a.internet_facing, a.edr_installed,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.asset_id = a.asset_id AND v.status = 'abierta')
                   AS open_vuln_count,
               (SELECT MAX(v.cvss) FROM vulnerabilities v WHERE v.asset_id = a.asset_id AND v.status = 'abierta')
                   AS max_cvss_open,
               (SELECT group_concat(v.reference || ':' || v.product || ':' || v.cvss, '; ') FROM vulnerabilities v
                 WHERE v.asset_id = a.asset_id AND v.status = 'abierta') AS cve_ids
        FROM assets a""",
    "dim_rule": """
        SELECT r.rule_id, r.name, r.base_severity, r.runbook_id AS runbook, b.title AS runbook_title,
               b.checks_text AS runbook_checks, b.decision_guidance_text AS runbook_decision
        FROM detection_rules r LEFT JOIN runbooks b ON b.runbook_id = r.runbook_id""",
    "bridge_alert_entity": """
        SELECT x.alert_id, 'user' AS entity_type, lower(u.username) AS entity_value, lower(u.username) AS user_key,
               NULL AS hostname, NULL AS context_key FROM alert_users x JOIN users u ON u.user_id = x.user_id
        UNION ALL SELECT x.alert_id, 'host', a.hostname, NULL, a.hostname, lower(a.ip)
               FROM alert_assets x JOIN assets a ON a.asset_id = x.asset_id
        UNION ALL SELECT alert_id, indicator_type, value, NULL, NULL, lower(value) FROM alert_indicators
        UNION ALL SELECT alert_id, 'file', COALESCE(sha256, file_name), NULL, NULL, lower(sha256) FROM alert_files
        UNION ALL SELECT alert_id, 'process', name, NULL, NULL, NULL FROM alert_processes
        UNION ALL SELECT alert_id, 'customer', customer_id, NULL, NULL, NULL FROM alert_customers
        UNION ALL SELECT alert_id, 'cloud_identity', identity, NULL, NULL, NULL FROM alert_cloud
        UNION ALL SELECT alert_id, 'ai_session', session_id, NULL, NULL, NULL FROM alert_ai_sessions""",
    "bridge_alert_event": """
        SELECT e.alert_id, e.position, e.event_id, s.state, s.reason, s.reference
        FROM alert_events e LEFT JOIN alert_log_selection s ON s.alert_id = e.alert_id AND s.event_id = e.event_id""",
    "bridge_alert_incident": "SELECT * FROM alert_incidents",
    "fact_alert": """
        SELECT a.alert_id, a.created_at, a.rule_id, a.severity AS rule_severity, a.status, d.dedup_hash
        FROM alerts a LEFT JOIN alert_dedup d ON d.alert_id = a.alert_id""",
    "v_alert_duplicates": """
        SELECT d.dedup_hash, COUNT(*) AS n, MIN(a.created_at) AS first_seen, MAX(a.created_at) AS last_seen,
               group_concat(a.alert_id, ',') AS alert_ids
        FROM alert_dedup d JOIN alerts a ON a.alert_id = d.alert_id GROUP BY d.dedup_hash HAVING COUNT(*) > 1""",
    "v_alert_change_overlap": """
        SELECT a.alert_id, c.change_id, c.title AS change_title, c.scope AS change_scope,
               (EXISTS (SELECT 1 FROM change_assets ca JOIN alert_assets aa ON aa.asset_id = ca.asset_id
                         WHERE ca.change_id = c.change_id AND aa.alert_id = a.alert_id)
                OR EXISTS (SELECT 1 FROM change_users cu JOIN alert_users au ON au.user_id = cu.user_id
                         WHERE cu.change_id = c.change_id AND au.alert_id = a.alert_id)
                OR EXISTS (SELECT 1 FROM alert_indicators i WHERE i.alert_id = a.alert_id AND length(i.value) > 3
                         AND instr(lower(c.title || ' ' || COALESCE(c.details, '') || ' ' || COALESCE(c.scope, '')),
                                   lower(i.value)) > 0)) AS entity_match
        FROM alerts a JOIN changes c ON a.created_at BETWEEN c.start_at AND c.end_at""",
    "v_alert_enriched": "SELECT * FROM alert_enriched",
}


def _create_views(conn: sqlite3.Connection) -> None:
    for name, sql in VIEWS.items():
        conn.execute(f'DROP VIEW IF EXISTS "{name}"')
        conn.execute(f'CREATE VIEW "{name}" AS {sql}')


# ---------------------------------------------------------------------------------------------- dim_context
def _create_dim_context(conn: sqlite3.Connection) -> None:
    conn.execute("DROP TABLE IF EXISTS dim_context")
    conn.execute(
        "CREATE TABLE dim_context (context_key TEXT NOT NULL, context_type TEXT NOT NULL, reputation TEXT, "
        "confidence REAL, malware_family TEXT, tags TEXT, last_seen TEXT, country TEXT, as_org TEXT, is_tor INTEGER, "
        "is_vpn_provider INTEGER, is_hosting INTEGER, sandbox_verdict TEXT, sandbox_family TEXT, change_title TEXT, "
        "change_start TEXT, change_end TEXT, change_scope TEXT, change_detail TEXT)"
    )
    tags: dict[str, list[str]] = {}
    for intel, tag in conn.execute("SELECT intelligence_id, tag FROM threat_intelligence_tags ORDER BY tag"):
        tags.setdefault(intel, []).append(tag)
    ti: dict[str, tuple] = {}
    for row in conn.execute(
        "SELECT lower(value), indicator_type, reputation, confidence, malware_family, intelligence_id, last_seen "
        "FROM threat_intelligence ORDER BY last_seen"
    ):
        ti[row[0]] = row  # the most recent record wins
    geo = {r[0]: r[1:] for r in conn.execute(
        "SELECT lower(ip), country, as_org, is_tor, is_vpn_provider, is_hosting FROM geoip")}  # fmt: skip
    sandbox: dict[str, tuple] = {}
    for key, verdict, family in conn.execute(
        "SELECT lower(sha256), verdict, malware_family FROM sandbox_reports WHERE sha256 IS NOT NULL ORDER BY analyzed_at"
    ):
        sandbox[key] = (verdict, family)
    rows = []
    for key in sorted(set(ti) | set(geo) | set(sandbox)):
        t, g, b = ti.get(key), geo.get(key), sandbox.get(key)
        kind = t[1] if t else "ip" if g else "sha256"
        rows.append((
            key, kind, t and t[2], t and t[3], t and t[4], t and ",".join(tags.get(t[5], [])), t and t[6],
            *(g or (None,) * 5), *(b or (None, None)), None, None, None, None, None,
        ))  # fmt: skip
    conn.executemany(f"INSERT INTO dim_context VALUES ({','.join('?' * 19)})", rows)
    conn.execute(
        "INSERT INTO dim_context (context_key, context_type, change_title, change_start, change_end, change_scope, "
        "change_detail) SELECT change_id, 'change', title, start_at, end_at, scope, details FROM changes"
    )
    conn.execute("CREATE INDEX idx_dim_context_key ON dim_context (context_key)")
    conn.execute("CREATE INDEX idx_dim_context_change ON dim_context (context_type, change_start, change_end)")


# ---------------------------------------------------------------------------------------------- per-alert tables
def _matrix(conn: sqlite3.Connection, data_dir: Path) -> dict[tuple[str, str], str]:
    from ..prompt_builder.policy import load_policy

    policy = load_policy(data_dir / "01_contexto" / "politica_soc.md")
    conn.execute("DROP TABLE IF EXISTS main.ref_severity_matrix")  # never an attached (read-only) database
    conn.execute(
        "CREATE TABLE main.ref_severity_matrix (rule_severity TEXT NOT NULL, criticality TEXT NOT NULL, "
        "base_severity TEXT NOT NULL, PRIMARY KEY (rule_severity, criticality))"
    )
    conn.executemany("INSERT INTO ref_severity_matrix VALUES (?, ?, ?)", [(*k, v) for k, v in policy.matrix.items()])
    return dict(policy.matrix)


def _create_alert_tables(conn: sqlite3.Connection, data_dir: Path, rebuild: bool) -> int:
    """Refresh alert lookups against current inventory and policy; return the newly added count."""
    from ..criticality_scope import load_db_scopes
    from ..prompt_builder.criticality import assess_criticality

    matrix = _matrix(conn, data_dir)
    if rebuild:
        conn.execute("DROP TABLE IF EXISTS alert_enriched")
        conn.execute("DROP TABLE IF EXISTS alert_dedup")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS alert_enriched (alert_id TEXT PRIMARY KEY, created_at TEXT, rule_id TEXT, "
        "rule_severity TEXT, technique_id TEXT, runbook_id TEXT, user_key TEXT, privileged INTEGER, vip INTEGER, "
        "hr_event TEXT, hostname TEXT, asset_criticality TEXT, business_service TEXT, context_key TEXT, "
        "reputation TEXT, sandbox_verdict TEXT, matrix_base_severity TEXT, is_ot INTEGER)"
    )
    conn.execute("CREATE TABLE IF NOT EXISTS alert_dedup (alert_id TEXT PRIMARY KEY, dedup_hash TEXT NOT NULL)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_dedup_hash ON alert_dedup (dedup_hash)")
    pending = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE alert_id NOT IN (SELECT alert_id FROM alert_enriched)"
    ).fetchone()[0]
    # Recompute existing lookups too: inventory, identities, service links and the matrix can change.
    alerts = conn.execute(
        "SELECT a.alert_id, a.created_at, a.rule_id, a.severity, r.technique_id, r.runbook_id "
        "FROM alerts a JOIN detection_rules r ON r.rule_id = a.rule_id ORDER BY a.alert_id"
    ).fetchall()
    services = {n: c for n, c in conn.execute("SELECT name, criticality FROM business_services")}
    scopes = load_db_scopes(conn)
    inventory_hosts = {
        row[0]: row for row in conn.execute("SELECT hostname,criticality,business_service,zone_id FROM assets")
    }
    users_by_alert, entities_by_alert = defaultdict(list), defaultdict(list)
    for aid, *user in conn.execute(
        "SELECT x.alert_id, d.user_key, d.privileged, d.vip, d.hr_event FROM alert_users x JOIN dim_user d "
        "ON d.user_id = x.user_id ORDER BY x.alert_id, d.privileged DESC, d.vip DESC, d.user_key"
    ):
        users_by_alert[aid].append(user)
    indicators = {}
    for aid, *indicator in conn.execute(
        "SELECT b.alert_id, b.context_key, c.reputation, c.sandbox_verdict FROM bridge_alert_entity b "
        "LEFT JOIN dim_context c ON c.context_key = b.context_key WHERE b.context_key IS NOT NULL "
        "ORDER BY b.alert_id, CASE c.reputation WHEN 'malicious' THEN 0 WHEN 'suspicious' THEN 1 ELSE 2 END, b.context_key"
    ):
        indicators.setdefault(aid, indicator)
    for aid, kind, value in conn.execute("SELECT alert_id, entity_type, entity_value FROM bridge_alert_entity"):
        entities_by_alert[aid].append(f"{kind}={value}")
    rows, dedup = [], []
    for alert_id, created, rule_id, severity, technique, runbook in alerts:
        scope = scopes[alert_id]
        hosts, users = [inventory_hosts[h] for h in sorted(scope.assets)], users_by_alert[alert_id]
        user = users[0] if users else (None, None, None, None)
        indicator = indicators.get(alert_id, (None, None, None))
        service_names = scope.services
        crit = assess_criticality(
            [(h[0], h[1]) for h in hosts],
            [(name, services.get(name)) for name in sorted(service_names)],
        ).level
        host = max(hosts, key=lambda h: CRITICALITY_RANK.get(h[1], 0)) if hosts else None
        service = max(
            sorted(service_names),
            key=lambda name: CRITICALITY_RANK.get(services[name], 0),
            default=host[2] if host else None,
        )
        is_ot = any(str(h[3] or "").upper().startswith("OT") or str(h[0]).upper().startswith(OT_MARKERS) for h in hosts)
        rows.append((
            alert_id, created, rule_id, severity, technique, runbook, *user, host and host[0], crit,
            service, *indicator,
            matrix.get((severity, crit)), int(is_ot),
        ))  # fmt: skip
        values = sorted(entities_by_alert[alert_id])
        key = f"{rule_id}|{created[:10]}|{';'.join(values)}"
        dedup.append((alert_id, hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]))
    columns = [r[1] for r in conn.execute("PRAGMA table_info(alert_enriched)")]
    updates = ", ".join(f"{name}=excluded.{name}" for name in columns if name != "alert_id")
    conn.executemany(
        f"INSERT INTO alert_enriched VALUES ({','.join('?' * 18)}) ON CONFLICT(alert_id) DO UPDATE SET {updates}", rows
    )
    conn.executemany(
        "INSERT INTO alert_dedup VALUES (?, ?) ON CONFLICT(alert_id) DO UPDATE SET dedup_hash=excluded.dedup_hash",
        dedup,
    )
    return pending


def _create_incidents(conn: sqlite3.Connection) -> None:
    """L2 links: duplicate groups and alerts covered by an approved change touching their entities."""
    conn.execute("DELETE FROM alert_incidents")
    conn.execute(
        "INSERT INTO alert_incidents SELECT d.alert_id, 'INC-DUP-' || d.dedup_hash, 'duplicado (misma regla, "
        "entidades y día)', 1.0, 1, 0 FROM alert_dedup d WHERE d.dedup_hash IN "
        "(SELECT dedup_hash FROM alert_dedup GROUP BY dedup_hash HAVING COUNT(*) > 1)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO alert_incidents SELECT alert_id, 'INC-' || change_id, 'cubierta por ' || change_id, "
        "0.8, 0, 1 FROM v_alert_change_overlap WHERE entity_match"
    )


def refresh(conn: sqlite3.Connection, data_dir: Path | None = None, rebuild: bool = False) -> dict[str, int]:
    """Create or update every derived object. Safe to call repeatedly."""
    data_dir = data_dir or ROOT / "docs"
    conn.executescript(PIPELINE_SQL.read_text(encoding="utf-8"))
    if rebuild:
        conn.execute("DROP TABLE IF EXISTS dim_log")
    added_logs = _create_dim_log(conn)
    _create_log_detail_view(conn)
    _create_dim_context(conn)
    _create_views(conn)
    added_alerts = _create_alert_tables(conn, data_dir, rebuild)
    _create_incidents(conn)
    conn.commit()
    return {"dim_log_added": added_logs, "alert_enriched_added": added_alerts}


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    target = db_path(path)
    if not target.exists():
        raise FileNotFoundError(f"Database not found: {target}. Create it with python -m src.database.build")
    conn = sqlite3.connect(target, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", type=Path, default=None)
    parser.add_argument("--data", type=Path, default=ROOT / "docs")
    parser.add_argument("--rebuild", action="store_true", help="recompute every materialised table")
    args = parser.parse_args()
    with connect(args.db) as conn:
        print(json.dumps(refresh(conn, args.data, args.rebuild)))


if __name__ == "__main__":
    main()
