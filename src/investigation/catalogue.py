"""Read-only catalogue for the N2 investigation: the triage catalogue plus multi-day and cross-alert queries.

Why: reconstructing an attack chain needs data the triage prompt never asks for: activity summarised per day over
long windows, the other alerts of the same entities with their triage verdict, the members of an incident and who
else used an IP or reached a destination (scope). The model still cannot write SQL: it picks a name from this
catalogue, values are bound with `?`, results are capped at MAX_ROWS and the connection is read-only.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

from ..llm_triage.db_backend import DbToolBackend, normalise_identity
from ..prompt_builder.schema import QUERIES, QuerySpec
from ..prompt_builder.tools import MAX_QUERIES_PER_REQUEST, MAX_ROWS, MIN_REASON_CHARS, TOOL_NAME

_DAILY = (
    "SELECT substr(timestamp, 1, 10) AS day, source, action, result, COUNT(*) AS events, MIN(timestamp) AS first_seen, "
    "MAX(timestamp) AS last_seen FROM dim_log WHERE {col} = ? AND timestamp BETWEEN ? AND ? GROUP BY 1, 2, 3, 4 "
    "ORDER BY 1, 6"
)
_ALERT_COLS = (
    "a.alert_id, a.created_at, a.rule_id, r.name AS rule_name, r.tactic, r.technique_id, a.severity AS rule_severity, "
    "t.verdict, t.severity AS ticket_severity, t.escalate"
)

EXTRA_QUERIES: dict[str, QuerySpec] = {
    "entity_alerts": QuerySpec(
        "Alertas de la misma entidad (usuario, host, IP, dominio, hash) en la ventana, con táctica y veredicto de triaje",
        f"SELECT DISTINCT {_ALERT_COLS} FROM bridge_alert_entity b JOIN alerts a ON a.alert_id = b.alert_id "
        "JOIN detection_rules r ON r.rule_id = a.rule_id LEFT JOIN triage_tickets t ON t.alert_id = a.alert_id "
        "WHERE b.entity_value = ? AND a.created_at BETWEEN ? AND ? ORDER BY a.created_at",
        ("entity_value", "window_start", "window_end"),
    ),
    "alert_brief": QuerySpec(
        "Resumen de otra alerta: regla, descripción y, si ya se trió, título, veredicto y resumen del ticket",
        f"SELECT {_ALERT_COLS}, a.description, json_extract(t.ticket_json, '$.title') AS ticket_title, "
        "json_extract(t.ticket_json, '$.summary') AS ticket_summary FROM alerts a JOIN detection_rules r "
        "ON r.rule_id = a.rule_id LEFT JOIN triage_tickets t ON t.alert_id = a.alert_id WHERE a.alert_id = ?",
        ("alert_id",),
    ),
    "incident_members": QuerySpec(
        "Alertas vinculadas a un incidente (duplicados o cambio autorizado) con su motivo",
        "SELECT i.alert_id, a.created_at, a.rule_id, r.name AS rule_name, i.link_reason, i.is_duplicate, i.is_authorised "
        "FROM alert_incidents i JOIN alerts a ON a.alert_id = i.alert_id JOIN detection_rules r ON r.rule_id = a.rule_id "
        "WHERE i.incident_id = ? ORDER BY a.created_at",
        ("incident_id",),
    ),
    "user_daily": QuerySpec(
        "Actividad diaria del usuario por fuente y acción (ventanas de varios días)",
        _DAILY.format(col="user_key"),
        ("user_key", "window_start", "window_end"),
    ),
    "host_daily": QuerySpec(
        "Actividad diaria del equipo por fuente y acción (ventanas de varios días)",
        _DAILY.format(col="hostname"),
        ("hostname", "window_start", "window_end"),
    ),
    "ip_daily": QuerySpec(
        "Actividad diaria de una IP de origen por fuente y acción (ventanas de varios días)",
        _DAILY.format(col="src_ip"),
        ("ip", "window_start", "window_end"),
    ),
    "ip_spread": QuerySpec(
        "Alcance de una IP de origen: usuarios y equipos que la usan, con primer y último evento",
        "SELECT user_key, hostname, COUNT(*) AS events, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen "
        "FROM dim_log WHERE src_ip = ? AND timestamp BETWEEN ? AND ? GROUP BY 1, 2 ORDER BY 4",
        ("ip", "window_start", "window_end"),
    ),
    "dst_hosts": QuerySpec(
        "Alcance de un destino (dominio, IP, URL): equipos y usuarios que lo contactan, con primer y último evento",
        "SELECT hostname, user_key, COUNT(*) AS events, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen "
        "FROM dim_log WHERE dst = ? GROUP BY 1, 2 ORDER BY 4",
        ("indicator",),
    ),
    "hash_hosts": QuerySpec(
        "Alcance de un fichero: equipos y usuarios donde aparece el hash, con primer y último evento",
        "SELECT hostname, user_key, source, COUNT(*) AS events, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen "
        "FROM dim_log WHERE sha256 = ? GROUP BY 1, 2, 3 ORDER BY 5",
        ("sha256",),
    ),
}

# Triage queries that also make sense for an investigation (runbook and severity matrix are triage concerns).
BASE_NAMES = tuple(n for n in QUERIES if n not in ("runbook_text", "severity_matrix"))
ALLOWED = tuple(sorted((*BASE_NAMES, *EXTRA_QUERIES)))


def spec(name: str) -> QuerySpec:
    return EXTRA_QUERIES.get(name) or QUERIES[name]


def signature(name: str) -> str:
    return f"{name}({', '.join(spec(name).params)})"


def tool_definition() -> dict[str, Any]:
    """`solicitar_contexto` with the investigation catalogue (same input contract as triage)."""
    catalogue = "; ".join(f"{signature(n)}: {spec(n).purpose}" for n in ALLOWED)
    query = {
        "type": "object",
        "properties": {
            "consulta": {"type": "string", "enum": list(ALLOWED)},
            "parametros": {"type": "array", "items": {"type": "string"}, "description": "valores en orden"},
        },
        "required": ["consulta", "parametros"],
    }
    return {
        "name": TOOL_NAME,
        "description": (
            "Lee la base de datos en solo lectura para reconstruir la cadena de ataque (máx. "
            f"{MAX_QUERIES_PER_REQUEST} consultas por petición, {MAX_ROWS} filas cada una). Indica siempre el motivo; "
            "se muestra al analista. Ventanas: timestamps ISO-8601 UTC (2026-10-05T00:00:00Z). Consultas: " + catalogue
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "motivo": {
                    "type": "string",
                    "minLength": MIN_REASON_CHARS,
                    "description": "qué parte de la cadena quieres comprobar y por qué",
                },  # fmt: skip
                "comprobacion": {"type": "string", "description": "fase: origen, propagación, alcance, relación..."},
                "consultas": {"type": "array", "items": query, "minItems": 1, "maxItems": MAX_QUERIES_PER_REQUEST},
            },
            "required": ["motivo", "consultas"],
        },
    }


class InvestigationBackend:
    """Executes the investigation catalogue on a read-only SQLite connection (one per thread)."""

    def __init__(self, db_path: str | Path) -> None:
        self.base = DbToolBackend(db_path)
        self.path = self.base.path
        self._local = threading.local()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, check_same_thread=False)
            self._local.conn = conn
        return conn

    def execute(self, consulta: str, parametros: list[str], allowed: list[str] | None = None) -> list[dict[str, Any]]:
        if consulta not in ALLOWED or (allowed is not None and consulta not in allowed):
            raise ValueError(f"consulta no permitida: {consulta}")
        if consulta in QUERIES:
            return self.base.execute(consulta, parametros)
        q = EXTRA_QUERIES[consulta]
        if len(parametros) != len(q.params):
            raise ValueError(f"{signature(consulta)} espera {len(q.params)} parámetros, recibió {len(parametros)}")
        values = [
            normalise_identity(str(v).strip()) if n == "user_key" else str(v).strip().lower() if n == "sha256"
            else str(v).strip() for n, v in zip(q.params, parametros, strict=True)
        ]  # fmt: skip
        cur = self._conn().execute(q.sql, values)
        cols = [d[0] for d in cur.description or ()]
        return [dict(zip(cols, row, strict=False)) for row in cur.fetchmany(MAX_ROWS)]

    def ticket(self, alert_id: str) -> dict[str, Any] | None:
        """Triage ticket of the alert (the N1 description the reconstruction starts from)."""
        row = (
            self._conn()
            .execute(
                "SELECT ticket_json, verdict, severity, escalate, decision FROM triage_tickets WHERE alert_id = ?",
                (alert_id,),
            )
            .fetchone()
        )
        if row is None:
            return None
        import json

        return {"ticket": json.loads(row[0] or "{}"), "verdict": row[1], "severity": row[2], "escalate": bool(row[3]),
                "decision": row[4]}  # fmt: skip

    def existing(self, table: str, column: str, values: list[str]) -> set[str]:
        """Which of `values` exist in table.column (used to reject invented event or alert ids)."""
        if table not in ("dim_log", "alerts", "alert_incidents") or column not in (
            "event_id",
            "alert_id",
            "incident_id",
        ):
            raise ValueError("tabla no permitida")
        found: set[str] = set()
        values = sorted({str(v) for v in values if v})
        for i in range(0, len(values), 500):
            chunk = values[i : i + 500]
            sql = f"SELECT DISTINCT {column} FROM {table} WHERE {column} IN ({','.join('?' * len(chunk))})"
            found |= {r[0] for r in self._conn().execute(sql, chunk)}
        return found
