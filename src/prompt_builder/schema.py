# ruff: noqa: S608 - SQL is assembled only from the trusted constants below; values are bound with ?N.
"""Read-only query catalogue offered to the LLM, written for the SQLite schema in src/database/schema.sql.

Why: the LLM has read access to the database, so the prompt carries identifiers plus named, parameterised queries
instead of copying data. Logs are split into one detail table per source (`vpn_logs`, `edr_logs`...), so the
activity queries read `LOG_VIEW`: a UNION ALL that projects every source to the same columns (user, host, src_ip,
dst, action, result, ref_id, sha256, customer_id). It is generated from `LOG_PROJECTION`, a trusted constant;
values are always bound with `?` (`?1`, `?2`... when a value is used twice). Every query selects explicit columns
and is capped at 50 rows.

`SchemaMap` is kept for compatibility: queries may still use `{table}` / `{table.column}` placeholders, but the
current catalogue is written with physical names and the default map leaves them unchanged.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..database.schema import DETAIL_SOURCES, MODEL_PATH

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)(?:\.([a-z_][a-z0-9_]*))?\}")
LIMIT = 50


def _safe(identifier: str) -> str:
    if not _IDENT.match(identifier):
        raise ValueError(f"unsafe SQL identifier in schema map: {identifier!r}")
    return identifier


@dataclass(frozen=True)
class SchemaMap:
    """Logical names -> physical names. Anything not mapped keeps its name."""

    tables: dict[str, str] = field(default_factory=dict)
    columns: dict[str, dict[str, str]] = field(default_factory=dict)

    def table(self, name: str) -> str:
        return _safe(self.tables.get(name, name))

    def column(self, table: str, name: str) -> str:
        return _safe(self.columns.get(table, {}).get(name, name))

    def render(self, template: str) -> str:
        """Replace `{table}` / `{table.column}` placeholders with physical identifiers."""

        def sub(m: re.Match[str]) -> str:
            return self.column(m[1], m[2]) if m[2] else self.table(m[1])

        return _PLACEHOLDER.sub(sub, template)

    @classmethod
    def from_json(cls, path: str | Path) -> SchemaMap:
        """Load a mapping file: {"tables": {...}, "columns": {"logs": {"timestamp": "ts"}}}."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(tables=data.get("tables", {}), columns=data.get("columns", {}))


@dataclass(frozen=True)
class QuerySpec:
    """Read-only query; `params` are the names of the values bound to `?1`, `?2`... in order."""

    purpose: str
    sql: str
    params: tuple[str, ...] = ()


# ------------------------------------------------------------------ cross-source log projection
LOG_COLUMNS = (
    "user_id",
    "user_raw",
    "asset_id",
    "src_ip",
    "dst",
    "action",
    "result",
    "ref_id",
    "sha256",
    "customer_id",
)


def _user(column: str) -> str:
    return f"(SELECT username FROM users WHERE user_id = d.{column})"


# source -> SQL expression over the detail row `d` for each LOG_COLUMNS entry (missing = NULL)
LOG_PROJECTION: dict[str, dict[str, str]] = {
    "vpn": {"user_id": "d.user_id", "src_ip": "d.src_ip", "dst": "d.assigned_ip", "action": "d.action",
            "result": "d.mfa_result"},
    "idp_signins": {"user_id": "d.user_id", "src_ip": "d.src_ip", "dst": "d.app", "action": "'signin'",
                    "result": "d.result", "ref_id": "d.session_id"},
    "idp_audit": {"user_id": "d.actor_user_id", "src_ip": "d.src_ip",
                  "dst": f"COALESCE({_user('target_user_id')}, d.target_resource)", "action": "d.operation"},
    "ad_events": {"user_id": "d.subject_user_id", "user_raw": "d.subject_unresolved", "asset_id": "d.source_asset_id",
                  "dst": f"COALESCE({_user('target_user_id')}, d.target_unresolved)",
                  "action": "d.event_description", "result": "CAST(d.event_code AS TEXT)"},
    "edr_events": {"user_id": "d.user_id", "user_raw": "d.unresolved_user", "asset_id": "d.asset_id",
                   "dst": "d.process_name", "action": "d.event_type", "result": "d.parent_name", "sha256": "d.sha256"},
    "proxy": {"user_id": "d.user_id", "user_raw": "d.unresolved_user", "asset_id": "d.asset_id", "src_ip": "d.src_ip",
              "dst": "d.domain", "action": "d.action", "result": "CAST(d.http_status AS TEXT)"},
    "dns": {"asset_id": "d.asset_id", "src_ip": "d.src_ip", "dst": "d.query", "action": "d.qtype", "result": "d.rcode"},
    "firewall": {"src_ip": "d.src_ip", "dst": "d.dst_ip || ':' || COALESCE(d.dst_port, '')", "action": "d.action",
                 "result": "d.firewall_rule"},
    "email": {"user_id": "(SELECT recipient_user_id FROM email_recipients r WHERE r.event_id = d.event_id "
                         "ORDER BY r.position LIMIT 1)",
              "src_ip": "d.sender_ip", "dst": f"COALESCE({_user('sender_user_id')}, d.sender_unresolved)",
              "action": "d.action", "result": "d.verdict", "ref_id": "d.message_id",
              "sha256": "(SELECT sha256 FROM email_attachments t WHERE t.event_id = d.event_id ORDER BY t.position LIMIT 1)"},
    "email_clicks": {"user_id": "d.user_id", "src_ip": "d.src_ip", "dst": "d.url", "action": "d.action",
                     "result": "d.verdict_at_click",
                     "ref_id": "(SELECT message_id FROM email_logs m WHERE m.event_id = d.email_event_id)"},
    "dlp": {"user_id": "d.user_id", "asset_id": "d.asset_id", "dst": "d.destination", "action": "d.action",
            "result": "d.policy"},
    "sql_audit": {"user_id": "d.user_id", "asset_id": "d.client_asset_id", "dst": "d.database || '.' || d.object",
                  "action": "d.statement_type", "result": "CAST(d.rows_returned AS TEXT)"},
    "waf": {"src_ip": "d.src_ip", "dst": "d.host || d.uri", "action": "d.action",
            "result": "CAST(d.http_status AS TEXT)"},
    "ecom_auth": {"src_ip": "d.src_ip", "dst": "d.email", "action": "'login'", "result": "d.result",
                  "customer_id": "d.customer_id"},
    "ecom_account": {"src_ip": "d.src_ip", "action": "d.event_type", "result": "CAST(d.amount AS TEXT)",
                     "customer_id": "d.customer_id"},
    "ai_gateway": {"src_ip": "d.src_ip", "dst": "d.model", "action": "d.guardrail_action",
                   "result": "d.guardrail_category", "ref_id": "d.session_id", "customer_id": "d.customer_id"},
    "cloudtrail": {"user_raw": "d.identity_name", "src_ip": "d.src_ip", "dst": "d.event_source",
                   "action": "d.event_name", "result": "d.error_code", "ref_id": "d.access_key_id"},
    "cicd_builds": {"asset_id": "d.runner_asset_id", "dst": "d.pipeline", "action": "d.step", "result": "d.status",
                    "ref_id": "d.build_id"},
}  # fmt: skip
SOURCE_TABLES = {source: table for table, source in DETAIL_SOURCES.items()}


def _log_union() -> str:
    parts = []
    for source, columns in LOG_PROJECTION.items():
        table = _safe(SOURCE_TABLES[source])
        exprs = ", ".join(f"{columns.get(c, 'NULL')} AS {c}" for c in LOG_COLUMNS)
        parts.append(f"SELECT d.event_id AS event_id, {exprs} FROM {table} d")
    return " UNION ALL ".join(parts)


LOG_VIEW = (
    "(SELECT p.event_id, l.source, l.timestamp, COALESCE(u.username, p.user_raw) AS user, u.upn AS upn, "
    "COALESCE(a.hostname, (SELECT hostname FROM assets WHERE ip = p.src_ip LIMIT 1)) AS host, p.src_ip, p.dst, "
    "p.action, p.result, p.ref_id, p.sha256, p.customer_id "
    f"FROM ({_log_union()}) p JOIN logs l ON l.event_id = p.event_id "
    "LEFT JOIN users u ON u.user_id = p.user_id LEFT JOIN assets a ON a.asset_id = p.asset_id)"
)
LOG_COLS = "v.event_id, v.source, v.timestamp, v.user, v.host, v.src_ip, v.dst, v.action, v.result"


def _detail_columns() -> dict[str, list[str]]:
    model = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    return {t["name"]: [f["name"] for f in t["fields"]] for t in model["tables"] if t["name"] in DETAIL_SOURCES}


def _log_detail() -> str:
    """CASE over the source: the full detail row as a JSON object (attacker-controlled values are data)."""
    columns = _detail_columns()
    extras = {
        "email": [
            "'recipients', (SELECT json_group_array(COALESCE((SELECT username FROM users WHERE user_id = "
            "r.recipient_user_id), r.recipient_unresolved)) FROM email_recipients r WHERE r.event_id = d.event_id)",
            "'urls', (SELECT json_group_array(url) FROM email_urls x WHERE x.event_id = d.event_id)",
            "'attachments', (SELECT json_group_array(json_object('file_name', file_name, 'sha256', sha256, 'size', "
            "size)) FROM email_attachments x WHERE x.event_id = d.event_id)",
        ],
        "ai_gateway": [
            "'tool_calls', (SELECT json_group_array(json_object('name', name, 'arguments', json(arguments_json), "
            "'result', result)) FROM ai_tool_calls x WHERE x.event_id = d.event_id)"
        ],
    }
    cases = []
    for table, source in DETAIL_SOURCES.items():
        pairs = [f"'{_safe(c)}', d.{_safe(c)}" for c in columns[table] if c != "event_id"]
        pairs += extras.get(source, [])
        cases.append(
            f"WHEN '{source}' THEN (SELECT json_object({', '.join(pairs)}) FROM {_safe(table)} d WHERE d.event_id = ?1)"
        )
    return "CASE l.source " + " ".join(cases) + " END"


SEVERITY_MATRIX = (
    "(SELECT column1 AS rule_severity, column2 AS criticality, column3 AS base_severity FROM (VALUES "
    "('informational','Baja','informational'), ('informational','Media','informational'), "
    "('informational','Alta','low'), ('informational','Crítica','low'), "
    "('low','Baja','informational'), ('low','Media','low'), ('low','Alta','low'), ('low','Crítica','medium'), "
    "('medium','Baja','low'), ('medium','Media','medium'), ('medium','Alta','medium'), ('medium','Crítica','high'), "
    "('high','Baja','medium'), ('high','Media','high'), ('high','Alta','high'), ('high','Crítica','critical'), "
    "('critical','Baja','high'), ('critical','Media','critical'), ('critical','Alta','critical'), "
    "('critical','Crítica','critical')))"
)
HUMAN_VERDICT = "(SELECT verdict FROM alert_history h WHERE h.alert_id = {alias}.alert_id) AS analyst_verdict"
ENTITY_MATCH = (
    "(EXISTS (SELECT 1 FROM alert_users au JOIN users u ON u.user_id = au.user_id WHERE au.alert_id = {alias}.alert_id "
    "AND (u.username = ?1 OR u.upn = ?1)) "
    "OR EXISTS (SELECT 1 FROM alert_assets aa JOIN assets s ON s.asset_id = aa.asset_id "
    "WHERE aa.alert_id = {alias}.alert_id AND (s.hostname = ?1 COLLATE NOCASE OR s.ip = ?1)) "
    "OR EXISTS (SELECT 1 FROM alert_indicators ai WHERE ai.alert_id = {alias}.alert_id AND ai.value = ?1 COLLATE NOCASE) "
    "OR EXISTS (SELECT 1 FROM alert_files af WHERE af.alert_id = {alias}.alert_id AND af.sha256 = ?1 COLLATE NOCASE) "
    "OR EXISTS (SELECT 1 FROM alert_customers ac WHERE ac.alert_id = {alias}.alert_id AND ac.customer_id = ?1))"
)
SHARED_ENTITY = (
    "(EXISTS (SELECT 1 FROM alert_users x JOIN alert_users y ON y.user_id = x.user_id "
    "WHERE x.alert_id = a.alert_id AND y.alert_id = o.alert_id) "
    "OR EXISTS (SELECT 1 FROM alert_assets x JOIN alert_assets y ON y.asset_id = x.asset_id "
    "WHERE x.alert_id = a.alert_id AND y.alert_id = o.alert_id) "
    "OR EXISTS (SELECT 1 FROM alert_indicators x JOIN alert_indicators y ON y.value = x.value "
    "WHERE x.alert_id = a.alert_id AND y.alert_id = o.alert_id))"
)


def _activity(where: str) -> str:
    return f"SELECT {LOG_COLS} FROM {LOG_VIEW} v WHERE {where} AND v.timestamp BETWEEN ?2 AND ?3 ORDER BY v.timestamp LIMIT {LIMIT}"


QUERIES: dict[str, QuerySpec] = {
    "alert_enriched": QuerySpec(
        "Alerta enriquecida: regla, MITRE, usuarios (privilegiada/VIP), activos (criticidad, zona), IOC con reputación "
        "del TIP y ficheros con veredicto de sandbox",
        "SELECT a.alert_id, a.created_at, a.rule_id, r.name AS rule_name, r.base_severity AS rule_severity, "
        "a.severity AS alert_severity, r.source_product, r.tactic, r.technique_id, r.technique_name, r.runbook_id, "
        "a.reported_user_count, "
        "(SELECT group_concat(u.username || CASE WHEN u.privileged = 1 THEN ' [privilegiada]' ELSE '' END || "
        "CASE WHEN u.vip = 1 THEN ' [VIP]' ELSE '' END, ', ') FROM alert_users au JOIN users u ON u.user_id = au.user_id "
        "WHERE au.alert_id = a.alert_id) AS users, "
        "(SELECT group_concat(s.hostname || ' (' || COALESCE(s.criticality, '?') || ', ' || COALESCE(s.zone_id, '?') || "
        "', ' || COALESCE(s.business_service, '?') || ')', ', ') FROM alert_assets aa JOIN assets s ON s.asset_id = aa.asset_id "
        "WHERE aa.alert_id = a.alert_id) AS assets, "
        "(SELECT group_concat(i.indicator_type || ':' || i.value || ' [' || COALESCE(t.reputation, 'desconocida') || ']', ', ') "
        "FROM alert_indicators i LEFT JOIN threat_intelligence t ON t.value = i.value COLLATE NOCASE "
        "WHERE i.alert_id = a.alert_id) AS indicators, "
        "(SELECT group_concat(COALESCE(f.file_name, '?') || ' ' || COALESCE(f.sha256, '') || ' [' || "
        "COALESCE(sr.verdict, 'sin informe') || ']', ', ') FROM alert_files f LEFT JOIN sandbox_reports sr "
        "ON sr.sha256 = f.sha256 WHERE f.alert_id = a.alert_id) AS files "
        "FROM alerts a JOIN detection_rules r ON r.rule_id = a.rule_id WHERE a.alert_id = ?1",
        ("alert_id",),
    ),
    "alert_entities": QuerySpec(
        "Entidades de la alerta resueltas contra el inventario y la inteligencia (usuario, activo, IOC, fichero, "
        "proceso, cliente, cloud, sesión IA)",
        "SELECT 'user' AS entity_type, u.username AS entity_value, u.account_type || CASE WHEN u.privileged = 1 THEN "
        "', privilegiada' ELSE '' END || CASE WHEN u.vip = 1 THEN ', VIP' ELSE '' END AS detail FROM alert_users au "
        "JOIN users u ON u.user_id = au.user_id WHERE au.alert_id = ?1 "
        "UNION ALL SELECT 'asset', s.hostname, COALESCE(s.ip, '') || ', ' || COALESCE(s.criticality, '?') || ', ' || "
        "COALESCE(s.zone_id, '?') || ', ' || COALESCE(s.business_service, '?') FROM alert_assets aa "
        "JOIN assets s ON s.asset_id = aa.asset_id WHERE aa.alert_id = ?1 "
        "UNION ALL SELECT i.indicator_type, i.value, 'TIP: ' || COALESCE(t.reputation || ' (' || t.confidence || ')', "
        "'desconocido') FROM alert_indicators i LEFT JOIN threat_intelligence t ON t.value = i.value COLLATE NOCASE "
        "WHERE i.alert_id = ?1 "
        "UNION ALL SELECT 'file', f.file_name, COALESCE(f.sha256, '') || ' ' || COALESCE(f.path, '') FROM alert_files f "
        "WHERE f.alert_id = ?1 "
        "UNION ALL SELECT 'process', p.name, 'padre ' || COALESCE(p.parent_name, '?') || ': ' || COALESCE(p.command_line, '') "
        "FROM alert_processes p WHERE p.alert_id = ?1 "
        "UNION ALL SELECT 'customer', c.customer_id, c.role FROM alert_customers c WHERE c.alert_id = ?1 "
        "UNION ALL SELECT 'cloud', COALESCE(c.identity, c.access_key, c.cloud_account), 'cuenta ' || "
        "COALESCE(c.cloud_account, '?') || ', clave ' || COALESCE(c.access_key, '?') || ', bucket ' || "
        "COALESCE(c.bucket, '?') || ', usuario nuevo ' || COALESCE(c.new_user, '?') FROM alert_cloud c WHERE c.alert_id = ?1 "
        "UNION ALL SELECT 'ai_session', s.session_id, NULL FROM alert_ai_sessions s WHERE s.alert_id = ?1 "
        f"LIMIT {LIMIT}",
        ("alert_id",),
    ),
    "alert_events": QuerySpec(
        "Todos los logs citados por la alerta, en orden, con usuario, equipo, origen, destino, acción y resultado",
        f"SELECT e.position, {LOG_COLS} FROM alert_events e JOIN {LOG_VIEW} v ON v.event_id = e.event_id "
        f"WHERE e.alert_id = ?1 ORDER BY e.position LIMIT {LIMIT}",
        ("alert_id",),
    ),
    "log_detail": QuerySpec(
        "Registro completo de un log (campo detail: JSON no confiable)",
        f"SELECT l.event_id, l.source, l.timestamp, {_log_detail()} AS detail FROM logs l WHERE l.event_id = ?1",
        ("event_id",),
    ),
    "user_profile": QuerySpec(
        "Identidad: rol, tipo de cuenta, privilegios, VIP, equipo asignado, responsable y eventos de RRHH",
        "SELECT u.username, u.upn, u.display_name, u.account_type, u.department, u.title, u.location, u.privileged, "
        "u.vip, u.mfa_method, u.status, w.hostname AS workstation, m.username AS manager, "
        "(SELECT group_concat(h.event_type || ' ' || COALESCE(h.effective_date, '') || ': ' || COALESCE(h.details, ''), "
        "' | ') FROM hr_events h WHERE h.user_id = u.user_id) AS hr_events, u.notes FROM users u "
        "LEFT JOIN assets w ON w.asset_id = u.workstation_asset_id LEFT JOIN users m ON m.user_id = u.manager_user_id "
        "WHERE u.username = ?1 OR u.upn = ?1",
        ("user_key",),
    ),
    "asset_profile": QuerySpec(
        "Activo: tipo, criticidad, zona, servicios de negocio, propietario, exposición, EDR y vulnerabilidades",
        "SELECT s.hostname, s.ip, s.type, s.os, s.criticality, s.zone_id AS zone, z.description AS zone_description, "
        "s.location, s.business_service, (SELECT group_concat(b.name || ' (' || COALESCE(b.criticality, '?') || ')', ', ') "
        "FROM asset_services x JOIN business_services b ON b.service_id = x.service_id WHERE x.asset_id = s.asset_id) "
        "AS services, o.username AS owner, s.internet_facing, s.edr_installed, "
        "(SELECT group_concat(v.reference || ' cvss ' || COALESCE(v.cvss, '?') || ' ' || COALESCE(v.status, ''), ', ') "
        "FROM vulnerabilities v WHERE v.asset_id = s.asset_id) AS vulnerabilities FROM assets s "
        "LEFT JOIN network_zones z ON z.zone_id = s.zone_id LEFT JOIN users o ON o.user_id = s.owner_user_id "
        "WHERE s.hostname = ?1 COLLATE NOCASE OR s.ip = ?1",
        ("hostname",),
    ),
    "indicator": QuerySpec(
        "Inteligencia de un indicador: TIP, GeoIP/ASN, sandbox y sandbox que lo contactaron (sin filas = desconocido, "
        "no limpio)",
        "SELECT 'tip' AS kind, t.indicator_type AS type, t.reputation AS verdict, t.confidence AS score, t.malware_family, "
        "COALESCE((SELECT group_concat(tag, ', ') FROM threat_intelligence_tags g WHERE g.intelligence_id = "
        "t.intelligence_id), '') || CASE WHEN t.note IS NULL THEN '' ELSE '; ' || t.note END AS detail, "
        "t.first_seen || ' -> ' || t.last_seen AS seen FROM threat_intelligence t WHERE t.value = ?1 COLLATE NOCASE "
        "UNION ALL SELECT 'geoip', 'ip', NULL, NULL, NULL, COALESCE(g.country, '?') || ' ' || COALESCE(g.city, '') || ' ' || "
        "COALESCE(g.asn, '') || ' ' || COALESCE(g.as_org, '') || ' tor=' || COALESCE(g.is_tor, '?') || ' vpn=' || "
        "COALESCE(g.is_vpn_provider, '?') || ' hosting=' || COALESCE(g.is_hosting, '?') || ' proxy_residencial=' || "
        "COALESCE(g.is_residential_proxy, '?'), NULL FROM geoip g WHERE g.ip = ?1 "
        "UNION ALL SELECT 'sandbox', 'sha256', r.verdict, r.score, r.malware_family, COALESCE(r.file_name, '') || '; ' || "
        "COALESCE(r.note, '') || '; ' || COALESCE((SELECT group_concat(description, ' | ') FROM sandbox_behaviors b "
        "WHERE b.report_id = r.report_id), ''), r.analyzed_at FROM sandbox_reports r WHERE r.sha256 = ?1 COLLATE NOCASE "
        "OR r.md5 = ?1 COLLATE NOCASE "
        "UNION ALL SELECT 'sandbox_network', n.indicator_type, r.verdict, r.score, r.malware_family, 'contactado por ' || "
        "COALESCE(r.file_name, '?') || ' ' || COALESCE(r.sha256, ''), r.analyzed_at FROM sandbox_network_indicators n "
        f"JOIN sandbox_reports r ON r.report_id = n.report_id WHERE n.value = ?1 COLLATE NOCASE LIMIT {LIMIT}",
        ("indicator",),
    ),
    "change_overlap": QuerySpec(
        "Cambios aprobados cuya ventana (UTC) contiene la alerta y si algún activo o usuario de la alerta está en su "
        "alcance",
        "SELECT c.change_id, c.title, c.start_at, c.end_at, c.requester, c.scope, c.details, "
        "(EXISTS (SELECT 1 FROM change_assets ca JOIN alert_assets aa ON aa.asset_id = ca.asset_id "
        "WHERE ca.change_id = c.change_id AND aa.alert_id = a.alert_id) OR EXISTS (SELECT 1 FROM change_users cu "
        "JOIN alert_users au ON au.user_id = cu.user_id WHERE cu.change_id = c.change_id AND au.alert_id = a.alert_id)) "
        "AS entity_match FROM alerts a JOIN changes c ON a.created_at BETWEEN c.start_at AND c.end_at "
        f"WHERE a.alert_id = ?1 ORDER BY entity_match DESC, c.start_at LIMIT {LIMIT}",
        ("alert_id",),
    ),
    "duplicates": QuerySpec(
        "Alertas duplicadas: misma regla, mismo día y alguna entidad en común (con el veredicto humano si existe)",
        "SELECT o.alert_id, o.created_at, o.severity, o.status, "
        + HUMAN_VERDICT.format(alias="o")
        + " FROM alerts a JOIN alerts o ON o.rule_id = a.rule_id AND substr(o.created_at, 1, 10) = "
        f"substr(a.created_at, 1, 10) AND o.alert_id <> a.alert_id WHERE a.alert_id = ?1 AND {SHARED_ENTITY} "
        f"ORDER BY o.created_at LIMIT {LIMIT}",
        ("alert_id",),
    ),
    "incident_links": QuerySpec(
        "Incidentes vinculados (la correlación entre alertas está fuera de alcance: cada alerta tiene su ticket)",
        "SELECT ?1 AS alert_id, 'sin incidentes: la correlación de alertas no está implementada; cada alerta tiene su "
        "propio ticket' AS note",
        ("alert_id",),
    ),
    "related_alerts": QuerySpec(
        "Otras alertas con la misma entidad (usuario, equipo, IP, IOC, hash, cliente) en la ventana",
        "SELECT a.alert_id, a.rule_id, r.name AS rule_name, r.base_severity, a.created_at, "
        + HUMAN_VERDICT.format(alias="a")
        + " FROM alerts a JOIN detection_rules r ON r.rule_id = a.rule_id WHERE a.alert_id <> ?4 AND a.created_at "
        f"BETWEEN ?2 AND ?3 AND {ENTITY_MATCH.format(alias='a')} ORDER BY a.created_at LIMIT {LIMIT}",
        ("entity_value", "window_start", "window_end", "alert_id"),
    ),
    "user_activity": QuerySpec(
        "Actividad del usuario en la ventana (logs almacenados de todas las fuentes)",
        _activity("(v.user = ?1 COLLATE NOCASE OR v.upn = ?1)"),
        ("user_key", "window_start", "window_end"),
    ),
    "host_activity": QuerySpec(
        "Actividad del equipo en la ventana (procesos, red, persistencia)",
        _activity("v.host = ?1 COLLATE NOCASE"),
        ("hostname", "window_start", "window_end"),
    ),
    "ip_activity": QuerySpec(
        "Actividad de una IP de origen en la ventana",
        _activity("v.src_ip = ?1"),
        ("ip", "window_start", "window_end"),
    ),
    "customer_activity": QuerySpec(
        "Actividad del cliente de e-commerce en la ventana",
        _activity("v.customer_id = ?1"),
        ("customer", "window_start", "window_end"),
    ),
    "dst_spread": QuerySpec(
        "Cuántos equipos, usuarios y eventos contactan un destino (dominio, IP, URL) en los logs almacenados",
        "SELECT COUNT(DISTINCT v.host) AS hosts, COUNT(DISTINCT v.user) AS users, COUNT(*) AS events, "
        f"MIN(v.timestamp) AS first_seen, MAX(v.timestamp) AS last_seen FROM {LOG_VIEW} v "
        "WHERE length(?1) >= 4 AND instr(lower(v.dst), lower(?1)) > 0",
        ("indicator",),
    ),
    "ref_activity": QuerySpec(
        "Eventos con la misma referencia (message_id, session_id, build_id o clave de acceso)",
        f"SELECT {LOG_COLS} FROM {LOG_VIEW} v WHERE v.ref_id = ?1 ORDER BY v.timestamp LIMIT {LIMIT}",
        ("ref_id",),
    ),
    "hash_activity": QuerySpec(
        "Dónde aparece un hash (ejecuciones, adjuntos de correo)",
        f"SELECT {LOG_COLS} FROM {LOG_VIEW} v WHERE v.sha256 = ?1 COLLATE NOCASE ORDER BY v.timestamp LIMIT {LIMIT}",
        ("sha256",),
    ),
    "changes_in_window": QuerySpec(
        "Cambios aprobados activos en la ventana (inicio y fin en UTC, convertidos desde hora de Madrid)",
        "SELECT c.change_id, c.title, c.start_at, c.end_at, c.requester, c.scope, c.details, "
        "(SELECT group_concat(s.hostname || ' (' || ca.role || ')', ', ') FROM change_assets ca JOIN assets s "
        "ON s.asset_id = ca.asset_id WHERE ca.change_id = c.change_id) AS assets, "
        "(SELECT group_concat(u.username, ', ') FROM change_users cu JOIN users u ON u.user_id = cu.user_id "
        "WHERE cu.change_id = c.change_id) AS users FROM changes c WHERE c.end_at >= ?1 AND c.start_at <= ?2 "
        f"ORDER BY c.start_at LIMIT {LIMIT}",
        ("window_start", "window_end"),
    ),
    "runbook_text": QuerySpec(
        "Comprobaciones y decisión del runbook de la regla",
        "SELECT r.rule_id, r.name AS rule_name, r.runbook_id, b.title, b.checks_text, b.decision_guidance_text "
        "FROM detection_rules r JOIN runbooks b ON b.runbook_id = r.runbook_id WHERE r.rule_id = ?1",
        ("rule_id",),
    ),
    "severity_matrix": QuerySpec(
        "Fila de la matriz de severidad (política §2) para la severidad de la regla",
        f"SELECT m.criticality, m.base_severity FROM {SEVERITY_MATRIX} m WHERE m.rule_severity = ?1",
        ("rule_severity",),
    ),
}

BASE_QUERIES = (
    "runbook_text", "alert_enriched", "alert_entities", "alert_events", "duplicates", "incident_links",
    "related_alerts",
)  # fmt: skip
