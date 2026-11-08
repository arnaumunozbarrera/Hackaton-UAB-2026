"""Ticket for an alert closed by the basic checks, in the same format the LLM must produce.

The ticket only states what the checks proved (which context record explains each event); it proposes no actions
and never escalates, since a guard would have kept the alert otherwise. The analyst still accepts or rejects it in
the UI, and only an accepted verdict is written to alert_history.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from ..database.schema import ROOT
from .rules import CheckResult

TICKET_SCHEMA_PATH = ROOT / "docs" / "01_contexto" / "ticket_salida.schema.json"
AUTO_CONFIDENCE = 0.9  # deterministic match against authoritative context; the analyst still reviews it

VERDICT_TEXT = {
    "benign_true_positive": "actividad real pero autorizada o explicada",
    "false_positive": "la detección no corresponde a actividad maliciosa",
}


def load_ticket_schema(path: Path = TICKET_SCHEMA_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def ticket_id(alert_id: str, prefix: str = "TKT-AUTO") -> str:
    return f"{prefix}-{alert_id.removeprefix('ALR-')}"


def _column(conn: sqlite3.Connection, sql: str, alert_id: str) -> list[str]:
    return [r[0] for r in conn.execute(sql, (alert_id,)) if r[0]]


def auto_ticket(conn: sqlite3.Connection, result: CheckResult) -> dict[str, Any]:
    """Ticket (ticket_salida.schema.json) for an alert the checks discarded."""
    if not result.discard or result.verdict is None or result.severity is None:
        raise ValueError(f"{result.alert_id} was not discarded by the basic checks")
    aid = result.alert_id
    rule = conn.execute(
        "SELECT r.name, r.base_severity, r.technique_id, r.runbook_id, a.severity FROM alerts a "
        "JOIN detection_rules r ON r.rule_id = a.rule_id WHERE a.alert_id = ?",
        (aid,),
    ).fetchone()
    name, base, technique, runbook, alert_severity = rule
    refs = ", ".join(result.references)
    users = _column(
        conn, "SELECT u.username FROM alert_users a JOIN users u ON u.user_id = a.user_id WHERE a.alert_id = ?", aid
    )
    hosts = _column(
        conn, "SELECT s.hostname FROM alert_assets a JOIN assets s ON s.asset_id = a.asset_id WHERE a.alert_id = ?", aid
    )
    services = _column(
        conn,
        "SELECT DISTINCT s.business_service FROM alert_assets a JOIN assets s ON s.asset_id = a.asset_id "
        "WHERE a.alert_id = ?",
        aid,
    )
    customers = _column(conn, "SELECT customer_id FROM alert_customers WHERE alert_id = ?", aid)
    n = len(result.explanations)
    return {
        "ticket_id": ticket_id(aid),
        "alert_ids": [aid],
        "title": f"{name}: actividad explicada por {refs}",
        "verdict": result.verdict,
        "confidence": AUTO_CONFIDENCE,
        "severity": result.severity,
        "severity_rationale": (
            f"Severidad de la regla {base} (alerta {alert_severity}); los {n} eventos están explicados por contexto "
            f"autoritativo ({VERDICT_TEXT[result.verdict]}), por lo que se rebaja a {result.severity}."
        ),
        "affected": {"users": users, "hosts": hosts, "business_services": services, "customers": customers},
        "summary": (
            f"La alerta {aid} ({result.rule_id}, {runbook}) se ha cerrado en las comprobaciones básicas. "
            f"Todos sus eventos ({n}) están explicados por: {refs}. "
            "No hay indicadores maliciosos en el TIP, ni activos OT, ni otra alerta high/critical sin explicar de la "
            "misma entidad en ±24 h, ni texto libre que revisar. Pendiente de confirmación por el analista."
        ),
        "evidence": [
            {"source": result.sources.get(eid, ""), "event_id": eid, "finding": f"{exp.reference} ({exp.category})"}
            for eid, exp in result.explanations.items()
        ],
        "mitre": [technique] if technique else [],
        "recommended_actions": [],
        "escalation": {"escalate": False, "reason": "Actividad explicada por contexto; sin guardas activas"},
        "open_questions": [],
    }
