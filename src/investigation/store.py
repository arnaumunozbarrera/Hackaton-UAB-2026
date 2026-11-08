"""Persistence of attack-chain reports (`attack_chains`, one row per alert, latest run wins)."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..triage_flow.store import now

DDL = """CREATE TABLE IF NOT EXISTS attack_chains (
  alert_id TEXT PRIMARY KEY,
  report_json TEXT NOT NULL CHECK (json_valid(report_json)),
  valid INTEGER NOT NULL,
  errors_json TEXT,
  model TEXT,
  trigger TEXT,
  attempts INTEGER,
  usage_json TEXT,
  transcript_json TEXT,
  elapsed_s REAL,
  created_at TEXT NOT NULL
)"""


def ensure(conn: sqlite3.Connection) -> None:
    conn.execute(DDL)
    conn.commit()


def save(conn: sqlite3.Connection, result: dict[str, Any], trigger: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO attack_chains (alert_id, report_json, valid, errors_json, model, trigger, attempts, "
        "usage_json, transcript_json, elapsed_s, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            result["alert_id"], json.dumps(result.get("report") or {}, ensure_ascii=False), int(bool(result["valid"])),
            json.dumps(result.get("errors") or [], ensure_ascii=False), result.get("model"), trigger,
            result.get("attempts"), json.dumps(result.get("usage") or {}, default=str),
            json.dumps(result.get("transcript") or [], ensure_ascii=False, default=str), result.get("elapsed_s"), now(),
        ),
    )  # fmt: skip
    conn.commit()


def get(conn: sqlite3.Connection, alert_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT alert_id, report_json, valid, errors_json, model, trigger, attempts, usage_json, transcript_json, "
        "elapsed_s, created_at FROM attack_chains WHERE alert_id = ?",
        (alert_id,),
    ).fetchone()
    if row is None:
        return None
    keys = ("alert_id", "report", "valid", "errors", "model", "trigger", "attempts", "usage", "transcript",
            "elapsed_s", "created_at")  # fmt: skip
    out = dict(zip(keys, row, strict=True))
    for key in ("report", "errors", "usage", "transcript"):
        out[key] = json.loads(out[key] or "null")
    out["valid"] = bool(out["valid"])
    return out


def chained(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT alert_id FROM attack_chains")}
