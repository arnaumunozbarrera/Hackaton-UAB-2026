"""Logical-to-physical database schema map and the read-only query catalogue offered to the LLM.

Why: the LLM has read access to the database, so the prompt carries identifiers plus ready-made parameterised
queries instead of copying data. The schema will change; queries are written against *logical* names
(`{dim_log}`, `{dim_log.timestamp}`) and rendered through a `SchemaMap`, so a new schema only needs a new
mapping (JSON) instead of new prompts. Identifiers come from the map and are validated; values are always `?`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)(?:\.([a-z_][a-z0-9_]*))?\}")


def _safe(identifier: str) -> str:
    if not _IDENT.match(identifier):
        raise ValueError(f"unsafe SQL identifier in schema map: {identifier!r}")
    return identifier


@dataclass(frozen=True)
class SchemaMap:
    """Logical names -> physical names. Anything not mapped keeps its logical name."""

    tables: dict[str, str] = field(default_factory=dict)
    columns: dict[str, dict[str, str]] = field(default_factory=dict)

    def table(self, name: str) -> str:
        return _safe(self.tables.get(name, name))

    def column(self, table: str, name: str) -> str:
        return _safe(self.columns.get(table, {}).get(name, name))

    def render(self, template: str) -> str:
        """Expand `[macros]`, then replace `{table}` / `{table.column}` placeholders with physical identifiers."""
        for macro, expansion in MACROS.items():
            template = template.replace(macro, expansion)

        def sub(m: re.Match[str]) -> str:
            return self.column(m[1], m[2]) if m[2] else self.table(m[1])

        return _PLACEHOLDER.sub(sub, template)

    @classmethod
    def from_json(cls, path: str | Path) -> SchemaMap:
        """Load a mapping file: {"tables": {...}, "columns": {"dim_log": {"timestamp": "ts"}}}."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(tables=data.get("tables", {}), columns=data.get("columns", {}))


@dataclass(frozen=True)
class QuerySpec:
    """Read-only query template; `params` are the names of the values bound to each `?`, in order."""

    purpose: str
    sql: str
    params: tuple[str, ...] = ()


MACROS: dict[str, str] = {
    "[log_cols]": (
        "{dim_log.event_id}, {dim_log.source}, {dim_log.timestamp}, {dim_log.user_key}, {dim_log.hostname}, "
        "{dim_log.src_ip}, {dim_log.dst}, {dim_log.action}, {dim_log.result}"
    ),
    "[window]": "{dim_log.timestamp} BETWEEN ? AND ? ORDER BY {dim_log.timestamp}",
}

QUERIES: dict[str, QuerySpec] = {
    "alert_enriched": QuerySpec(
        "Alerta enriquecida: regla, MITRE, usuario, activo, IOC, severidad de matriz y runbook",
        "SELECT {v_alert_enriched.created_at}, {v_alert_enriched.rule_id}, {v_alert_enriched.rule_severity}, "
        "{v_alert_enriched.technique_id}, {v_alert_enriched.user_key}, {v_alert_enriched.privileged}, {v_alert_enriched.vip}, "
        "{v_alert_enriched.hr_event}, {v_alert_enriched.hostname}, {v_alert_enriched.asset_criticality}, "
        "{v_alert_enriched.business_service}, {v_alert_enriched.context_key}, {v_alert_enriched.reputation}, "
        "{v_alert_enriched.sandbox_verdict}, {v_alert_enriched.matrix_base_severity} FROM {v_alert_enriched} "
        "WHERE {v_alert_enriched.alert_id} = ?",
        ("alert_id",),
    ),
    "alert_entities": QuerySpec(
        "Entidades de la alerta resueltas a usuario, activo o contexto",
        "SELECT {bridge_alert_entity.entity_type}, {bridge_alert_entity.entity_value}, {bridge_alert_entity.user_key}, "
        "{bridge_alert_entity.hostname}, {bridge_alert_entity.context_key} FROM {bridge_alert_entity} "
        "WHERE {bridge_alert_entity.alert_id} = ?",
        ("alert_id",),
    ),
    "alert_events": QuerySpec(
        "Todos los logs citados por la alerta (incluidos los apartados como ruido)",
        "SELECT l.{dim_log.event_id}, l.{dim_log.source}, l.{dim_log.timestamp}, l.{dim_log.action}, l.{dim_log.result}, "
        "l.{dim_log.dst} FROM {bridge_alert_event} b JOIN {dim_log} l ON l.{dim_log.event_id} = b.{bridge_alert_event.event_id} "
        "WHERE b.{bridge_alert_event.alert_id} = ?",
        ("alert_id",),
    ),
    "log_detail": QuerySpec(
        "Registro completo de un log (campo detail: JSON no confiable)",
        "SELECT {dim_log.source}, {dim_log.timestamp}, {dim_log.detail} FROM {dim_log} WHERE {dim_log.event_id} = ?",
        ("event_id",),
    ),
    "user_profile": QuerySpec(
        "Identidad: rol, tipo de cuenta, privilegios, VIP, evento de RRHH",
        "SELECT {dim_user.account_type}, {dim_user.department}, {dim_user.title}, {dim_user.privileged}, {dim_user.vip}, "
        "{dim_user.status}, {dim_user.workstation}, {dim_user.hr_event}, {dim_user.hr_fecha_efectiva}, {dim_user.hr_detalle} "
        "FROM {dim_user} WHERE {dim_user.user_key} = ?",
        ("user_key",),
    ),
    "asset_profile": QuerySpec(
        "Activo: criticidad, servicio de negocio, zona, exposición, vulnerabilidades abiertas",
        "SELECT {dim_vulnerability.type}, {dim_vulnerability.criticality}, {dim_vulnerability.zone}, "
        "{dim_vulnerability.business_service}, {dim_vulnerability.internet_facing}, {dim_vulnerability.edr_installed}, "
        "{dim_vulnerability.open_vuln_count}, {dim_vulnerability.max_cvss_open}, {dim_vulnerability.cve_ids} "
        "FROM {dim_vulnerability} WHERE {dim_vulnerability.hostname} = ?",
        ("hostname",),
    ),
    "indicator": QuerySpec(
        "Inteligencia de un indicador: TIP, GeoIP/ASN, sandbox (NULL = desconocido, no limpio)",
        "SELECT {dim_context.context_type}, {dim_context.reputation}, {dim_context.confidence}, {dim_context.malware_family}, "
        "{dim_context.tags}, {dim_context.last_seen}, {dim_context.country}, {dim_context.as_org}, {dim_context.is_tor}, "
        "{dim_context.is_vpn_provider}, {dim_context.is_hosting}, {dim_context.sandbox_verdict}, {dim_context.sandbox_family} "
        "FROM {dim_context} WHERE {dim_context.context_key} = ?",
        ("indicator",),
    ),
    "change_overlap": QuerySpec(
        "Cambios aprobados cuya ventana contiene la alerta y si alguna entidad coincide con su alcance",
        "SELECT {v_alert_change_overlap.change_id}, {v_alert_change_overlap.change_title}, {v_alert_change_overlap.change_scope}, "
        "{v_alert_change_overlap.entity_match} FROM {v_alert_change_overlap} WHERE {v_alert_change_overlap.alert_id} = ?",
        ("alert_id",),
    ),
    "duplicates": QuerySpec(
        "Alertas duplicadas (misma regla, entidades y día)",
        "SELECT {v_alert_duplicates.n}, {v_alert_duplicates.first_seen}, {v_alert_duplicates.last_seen}, "
        "{v_alert_duplicates.alert_ids} FROM {v_alert_duplicates} WHERE {v_alert_duplicates.dedup_hash} = "
        "(SELECT {fact_alert.dedup_hash} FROM {fact_alert} WHERE {fact_alert.alert_id} = ?)",
        ("alert_id",),
    ),
    "incident_links": QuerySpec(
        "Incidentes a los que ya está vinculada la alerta (correlación L2)",
        "SELECT {bridge_alert_incident.incident_id}, {bridge_alert_incident.link_reason}, {bridge_alert_incident.link_score}, "
        "{bridge_alert_incident.is_duplicate}, {bridge_alert_incident.is_authorised} FROM {bridge_alert_incident} "
        "WHERE {bridge_alert_incident.alert_id} = ?",
        ("alert_id",),
    ),
    "related_alerts": QuerySpec(
        "Otras alertas con la misma entidad en la ventana",
        "SELECT DISTINCT a.{fact_alert.alert_id}, a.{fact_alert.rule_id}, a.{fact_alert.rule_severity}, "
        "a.{fact_alert.created_at} FROM {bridge_alert_entity} b JOIN {fact_alert} a "
        "ON a.{fact_alert.alert_id} = b.{bridge_alert_entity.alert_id} WHERE b.{bridge_alert_entity.entity_value} = ? "
        "AND a.{fact_alert.created_at} BETWEEN ? AND ? AND a.{fact_alert.alert_id} <> ? ORDER BY a.{fact_alert.created_at}",
        ("entity_value", "window_start", "window_end", "alert_id"),
    ),
    "user_activity": QuerySpec(
        "Actividad del usuario en la ventana (todas las fuentes)",
        "SELECT [log_cols] FROM {dim_log} WHERE {dim_log.user_key} = ? AND [window]",
        ("user_key", "window_start", "window_end"),
    ),
    "host_activity": QuerySpec(
        "Actividad del equipo en la ventana (procesos, red, persistencia)",
        "SELECT [log_cols] FROM {dim_log} WHERE {dim_log.hostname} = ? AND [window]",
        ("hostname", "window_start", "window_end"),
    ),
    "ip_activity": QuerySpec(
        "Actividad de una IP de origen en la ventana",
        "SELECT [log_cols] FROM {dim_log} WHERE {dim_log.src_ip} = ? AND [window]",
        ("ip", "window_start", "window_end"),
    ),
    "customer_activity": QuerySpec(
        "Actividad del cliente de e-commerce en la ventana",
        "SELECT [log_cols] FROM {dim_log} WHERE {dim_log.customer_id} = ? AND [window]",
        ("customer", "window_start", "window_end"),
    ),
    "dst_spread": QuerySpec(
        "Cuántos equipos y eventos contactan un destino (dominio, IP, URL) en todo el periodo",
        "SELECT COUNT(DISTINCT {dim_log.hostname}) AS hosts, COUNT(*) AS events, MIN({dim_log.timestamp}) AS first_seen, "
        "MAX({dim_log.timestamp}) AS last_seen FROM {dim_log} WHERE {dim_log.dst} = ?",
        ("indicator",),
    ),
    "ref_activity": QuerySpec(
        "Eventos con la misma referencia (message_id, session_id o build_id)",
        "SELECT [log_cols] FROM {dim_log} WHERE {dim_log.ref_id} = ? ORDER BY {dim_log.timestamp}",
        ("ref_id",),
    ),
    "hash_activity": QuerySpec(
        "Dónde aparece un hash (ejecuciones, descargas, correos)",
        "SELECT [log_cols] FROM {dim_log} WHERE {dim_log.sha256} = ? ORDER BY {dim_log.timestamp}",
        ("sha256",),
    ),
    "changes_in_window": QuerySpec(
        "Cambios aprobados activos en la ventana (change_start/end en hora local de Madrid)",
        "SELECT {dim_context.context_key}, {dim_context.change_title}, {dim_context.change_start}, {dim_context.change_end}, "
        "{dim_context.change_scope}, {dim_context.change_detail} FROM {dim_context} WHERE {dim_context.context_type} = 'change' "
        "AND {dim_context.change_start} <= ? AND {dim_context.change_end} >= ?",
        ("window_end", "window_start"),
    ),
    "runbook_text": QuerySpec(
        "Comprobaciones y decisión del runbook de la regla",
        "SELECT {dim_rule.runbook}, {dim_rule.runbook_checks}, {dim_rule.runbook_decision} FROM {dim_rule} "
        "WHERE {dim_rule.rule_id} = ?",
        ("rule_id",),
    ),
    "severity_matrix": QuerySpec(
        "Fila de la matriz de severidad para la severidad de la regla",
        "SELECT {ref_severity_matrix.criticality}, {ref_severity_matrix.base_severity} FROM {ref_severity_matrix} "
        "WHERE {ref_severity_matrix.rule_severity} = ?",
        ("rule_severity",),
    ),
}

BASE_QUERIES = (
    "runbook_text", "alert_enriched", "alert_entities", "alert_events", "duplicates", "incident_links",
    "related_alerts",
)  # fmt: skip
