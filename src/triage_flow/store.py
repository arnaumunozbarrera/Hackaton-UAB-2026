"""Ticket persistence and the read models used by the front (queue, history, statistics, decisions)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from . import severity_audit

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
DECISIONS = ("approve", "reject", "escalate", "investigate")
HISTORY_VERDICTS = ("true_positive", "false_positive", "benign_true_positive")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def save_ticket(conn: sqlite3.Connection, alert_id: str, ticket: dict[str, Any] | None, *, valid: bool,
                route: str, model: str = "", errors: list[str] | None = None, attempts: int = 0,
                usage: dict | None = None, transcript: list | None = None, elapsed_s: float = 0.0,
                severity_assessment: dict[str, Any] | None = None) -> None:  # fmt: skip
    """Store (or replace) the latest ticket of an alert. A re-triage clears any previous operator decision."""
    body = ticket if isinstance(ticket, dict) else {}
    with conn:
        _save_ticket(conn, alert_id, body, valid, route, model, errors, attempts, usage, transcript, elapsed_s)
        if valid and severity_assessment is not None:
            severity_audit.append_assessment(conn, alert_id, body, severity_assessment, now())


def _save_ticket(conn, alert_id, body, valid, route, model, errors, attempts, usage, transcript, elapsed_s):
    conn.execute(
        "INSERT OR REPLACE INTO triage_tickets (alert_id, ticket_json, valid, errors_json, route, model, verdict, "
        "severity, confidence, escalate, attempts, usage_json, transcript_json, elapsed_s, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            alert_id, json.dumps(body, ensure_ascii=False), int(valid), json.dumps(errors or [], ensure_ascii=False),
            route, model, body.get("verdict"), body.get("severity"), body.get("confidence"),
            int(bool((body.get("escalation") or {}).get("escalate"))), attempts,
            json.dumps(usage or {}), json.dumps(transcript or [], ensure_ascii=False, default=str), elapsed_s, now(),
        ),
    )  # fmt: skip


def _ticket_row(row: sqlite3.Row) -> dict[str, Any]:
    out = dict(row)
    out["ticket"] = json.loads(out.pop("ticket_json") or "{}")
    out["errors"] = json.loads(out.pop("errors_json") or "[]")
    for key in ("usage_json", "transcript_json"):
        if key in out:
            out[key[:-5]] = json.loads(out.pop(key) or "null")
    return out


_BASE = (
    "SELECT t.alert_id, t.ticket_json, t.valid, t.errors_json, t.route, t.model, t.verdict, t.severity, t.confidence, "
    "t.escalate, t.attempts, t.elapsed_s, t.created_at, t.decision, t.decision_comment, t.decided_by, t.decided_at, "
    "a.created_at AS alert_created_at, a.rule_id, r.name AS rule_name, r.source_product, r.tactic, r.runbook_id, "
    "a.severity AS rule_severity, "
    "(SELECT COUNT(*) FROM alert_log_selection s WHERE s.alert_id = t.alert_id AND s.state IN ('kept','unfiltered')) "
    "AS informative_logs, (SELECT COUNT(*) FROM alert_events e WHERE e.alert_id = t.alert_id) AS cited_logs "
    "FROM triage_tickets t JOIN alerts a ON a.alert_id = t.alert_id JOIN detection_rules r ON r.rule_id = a.rule_id"
)
_ORDER = (
    " ORDER BY CASE t.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 "
    "ELSE 4 END, t.escalate DESC, a.created_at"
)


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    try:
        return [_ticket_row(r) for r in conn.execute(sql, params)]
    finally:
        conn.row_factory = None


def queue(conn: sqlite3.Connection, limit: int = 200) -> list[dict[str, Any]]:
    """Tickets waiting for an operator: no decision yet and not auto-closed by the discriminator. Criticality order."""
    return _rows(conn, _BASE + " WHERE t.decision IS NULL AND t.route = 'llm'" + _ORDER + " LIMIT ?", (limit,))


def history(conn: sqlite3.Connection, limit: int = 500) -> list[dict[str, Any]]:
    """Decided tickets and auto-closed tickets, newest first."""
    sql = (
        _BASE
        + " WHERE t.decision IS NOT NULL OR t.route = 'discriminator' ORDER BY COALESCE(t.decided_at, t.created_at) DESC LIMIT ?"
    )
    return _rows(conn, sql, (limit,))


def get_ticket(conn: sqlite3.Connection, alert_id: str) -> dict[str, Any] | None:
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            _BASE.replace("t.elapsed_s,", "t.elapsed_s, t.usage_json, t.transcript_json,") + " WHERE t.alert_id = ?",
            (alert_id,),
        ).fetchone()
    finally:
        conn.row_factory = None
    if row is None:
        return None
    out = _ticket_row(row)
    out["severity_assessments"] = severity_audit.history(conn, alert_id)
    out["selection"] = [
        dict(zip(("event_id", "source", "timestamp", "state", "reason", "reference"), r, strict=True))
        for r in conn.execute(
            "SELECT event_id, source, timestamp, state, reason, reference FROM alert_log_selection WHERE alert_id = ? "
            "ORDER BY timestamp",
            (alert_id,),
        )
    ]
    return out


def decide(conn: sqlite3.Connection, alert_id: str, decision: str, comment: str = "", operator: str = "") -> dict:
    """Record the operator decision. Approving a ticket with a final verdict writes it to alert_history."""
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {DECISIONS}")
    row = conn.execute("SELECT verdict FROM triage_tickets WHERE alert_id = ?", (alert_id,)).fetchone()
    if row is None:
        raise KeyError(alert_id)
    conn.execute(
        "UPDATE triage_tickets SET decision = ?, decision_comment = ?, decided_by = ?, decided_at = ? WHERE alert_id = ?",
        (decision, comment, operator, now(), alert_id),
    )
    if decision == "approve" and row[0] in HISTORY_VERDICTS:
        conn.execute("INSERT OR REPLACE INTO alert_history (alert_id, verdict) VALUES (?, ?)", (alert_id, row[0]))
    conn.commit()
    return {
        "alert_id": alert_id,
        "decision": decision,
        "history_written": decision == "approve" and row[0] in HISTORY_VERDICTS,
    }


def stats(conn: sqlite3.Connection) -> dict[str, Any]:
    one = lambda sql: conn.execute(sql).fetchone()[0]  # noqa: E731
    group = lambda sql: dict(conn.execute(sql).fetchall())  # noqa: E731
    return {
        "alerts_total": one("SELECT COUNT(*) FROM alerts"),
        "alerts_triaged": one("SELECT COUNT(*) FROM triage_tickets"),
        "alerts_pending_triage": one(
            "SELECT COUNT(*) FROM alerts WHERE alert_id NOT IN (SELECT alert_id FROM triage_tickets)"
        ),
        "awaiting_decision": one("SELECT COUNT(*) FROM triage_tickets WHERE decision IS NULL AND route = 'llm'"),
        "auto_resolved": one("SELECT COUNT(*) FROM triage_tickets WHERE route = 'discriminator'"),
        "escalated": one("SELECT COUNT(*) FROM triage_tickets WHERE escalate = 1"),
        "invalid_tickets": one("SELECT COUNT(*) FROM triage_tickets WHERE valid = 0"),
        "avg_triage_seconds": one("SELECT ROUND(AVG(elapsed_s), 2) FROM triage_tickets WHERE route = 'llm'") or 0,
        "by_verdict": group("SELECT COALESCE(verdict, 'none'), COUNT(*) FROM triage_tickets GROUP BY 1"),
        "by_severity": group("SELECT COALESCE(severity, 'none'), COUNT(*) FROM triage_tickets GROUP BY 1"),
        "by_route": group("SELECT route, COUNT(*) FROM triage_tickets GROUP BY 1"),
        "by_decision": group("SELECT COALESCE(decision, 'pending'), COUNT(*) FROM triage_tickets GROUP BY 1"),
        "alerts_by_rule_severity": group("SELECT severity, COUNT(*) FROM alerts GROUP BY 1"),
        "alerts_by_tactic": group(
            "SELECT r.tactic, COUNT(*) FROM alerts a JOIN detection_rules r ON r.rule_id = a.rule_id GROUP BY 1 "
            "ORDER BY 2 DESC LIMIT 6"
        ),
        "alerts_by_day": group("SELECT substr(created_at, 1, 10), COUNT(*) FROM alerts GROUP BY 1 ORDER BY 1"),
        "triaged_by_day": group(
            "SELECT substr(a.created_at, 1, 10), COUNT(*) FROM triage_tickets t JOIN alerts a ON a.alert_id = t.alert_id "
            "GROUP BY 1 ORDER BY 1"
        ),
        "alerts_by_severity_triaged": group(
            "SELECT a.severity, COUNT(*) FROM triage_tickets t JOIN alerts a ON a.alert_id = t.alert_id GROUP BY 1"
        ),
        "selection": group("SELECT state, COUNT(*) FROM alert_log_selection GROUP BY 1"),
        "embeddings": one("SELECT COUNT(*) FROM alert_embeddings"),
    }
