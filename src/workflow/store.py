"""Write triage results to the `triage` tables (schema group "Resultados del triaje").

Model outputs (checks, LLM transcript, tickets) are kept apart from source observations (`alerts`, logs) and from
human decisions (`analyst_decisions`, `executed_actions`, `alert_history`). Every function commits its own
transaction so a crash in the middle of an alert leaves the earlier stages stored.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..checks import CheckResult
from ..database.schema import SEVERITIES

TICKET_VERDICTS = ("true_positive", "false_positive", "benign_true_positive", "needs_more_info")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Read-write connection in WAL mode (the web UI reads while the workflow writes)."""
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def start_run(conn: sqlite3.Connection, alert_id: str, stage: str, model: str) -> int:
    cur = conn.execute(
        "INSERT INTO triage_runs (alert_id, stage, model, status, started_at) VALUES (?, ?, ?, 'running', ?)",
        (alert_id, stage, model, now()),
    )
    conn.commit()
    return int(cur.lastrowid)


def finish_run(
    conn: sqlite3.Connection,
    run_id: int,
    status: str,
    *,
    valid: bool | None = None,
    errors: list[str] | None = None,
    usage: dict[str, Any] | None = None,
    elapsed_s: float | None = None,
    transcript: list[dict[str, Any]] | None = None,
) -> None:
    conn.execute(
        "UPDATE triage_runs SET status = ?, finished_at = ?, valid = ?, errors_json = ?, usage_json = ?, "
        "elapsed_s = ?, transcript_json = ? WHERE run_id = ?",
        (
            status,
            now(),
            None if valid is None else int(valid),
            dumps(errors or []),
            dumps(usage or {}),
            elapsed_s,
            None if transcript is None else dumps(transcript),
            run_id,
        ),
    )
    conn.commit()


def save_checks(conn: sqlite3.Connection, run_id: int, result: CheckResult) -> None:
    conn.execute(
        "INSERT INTO triage_checks (run_id, discard, verdict, severity, reasons_json, references_json, guards_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            run_id,
            int(result.discard),
            result.verdict,
            result.severity,
            dumps(result.reasons),
            dumps(result.references),
            dumps(result.guards),
        ),
    )
    conn.commit()


def storable(ticket: Any) -> bool:
    """A ticket can be stored when its verdict and severity are in the closed domains (even if otherwise invalid)."""
    return (
        isinstance(ticket, dict) and ticket.get("verdict") in TICKET_VERDICTS and ticket.get("severity") in SEVERITIES
    )


def save_ticket(conn: sqlite3.Connection, run_id: int, alert_id: str, ticket: dict[str, Any], valid: bool) -> None:
    confidence = ticket.get("confidence")
    confidence = min(max(float(confidence), 0.0), 1.0) if isinstance(confidence, int | float) else None
    conn.execute(
        "INSERT INTO triage_tickets (run_id, alert_id, ticket_id, ticket_json, verdict, severity, ticket_confidence, "
        "valid, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id,
            alert_id,
            str(ticket.get("ticket_id") or ""),
            dumps(ticket),
            ticket["verdict"],
            ticket["severity"],
            confidence,
            int(valid),
            now(),
        ),
    )
    conn.commit()


def save_context_requests(conn: sqlite3.Connection, run_id: int, transcript: list[dict[str, Any]]) -> int:
    """One row per type-2 response (`contexto` entries of the transcript), numbered in order, rejected ones included
    (a rejected request does not consume budget, so the transcript's own `n` can repeat)."""
    rows = [
        (
            run_id,
            i,
            e.get("motivo"),
            e.get("comprobacion"),
            dumps(e.get("consultas") or []),
            dumps(e.get("resultados") or []),
            int(bool(e.get("is_error"))),
        )
        for i, e in enumerate((e for e in transcript if e.get("type") == "contexto"), 1)
    ]
    conn.executemany(
        "INSERT INTO triage_context_requests (run_id, n, motivo, comprobacion, consultas_json, rows_json, is_error) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    return len(rows)
