"""Rebuild a log event in its original API/`docs/04_logs` shape from the database rows.

Why: the N4 rules in `src.log_noise_discard` were written (and validated) against the raw events. Storage splits
each event into the `logs` hub, a per-source detail table and child tables, resolving users and hosts to inventory
ids. Reversing `src.database.logs.SPECS` gives the rules the same dicts they were tested on, without copying them.

Differences that remain (none matters to the rules): empty strings come back as None in JSON sources, timestamps
are normalised to UTC with a `Z` suffix, and a resolved user is written in the format each source uses.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..database.logs import SPECS
from ..database.schema import BOOLEAN_FIELDS

CSV_SOURCES = {"dns", "proxy", "firewall"}  # the API serves these rows as strings, like csv.DictReader
UPN_SOURCES = {"email", "email_clicks", "idp_signins", "idp_audit"}
DOMAIN_SOURCES = {"edr_events"}  # "TARVIA\\user"


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    cur = conn.execute(sql, params)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]


def _one(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
    rows = _rows(conn, sql, params)
    return rows[0] if rows else None


def _value(column: str, value: Any) -> Any:
    if value is None:
        return None
    if column.endswith("_json"):
        return json.loads(value)
    if column in BOOLEAN_FIELDS:
        return bool(value)
    return value


def _user(conn: sqlite3.Connection, source: str, user_id: str | None) -> str | None:
    if user_id is None:
        return None
    row = _one(conn, "SELECT username, upn FROM users WHERE user_id = ?", (user_id,))
    if row is None:
        return None
    if source in UPN_SOURCES:
        return row["upn"]
    return f"TARVIA\\{row['username']}" if source in DOMAIN_SOURCES else row["username"]


def _host(conn: sqlite3.Connection, asset_id: str | None) -> str | None:
    if asset_id is None:
        return None
    row = _one(conn, "SELECT hostname FROM assets WHERE asset_id = ?", (asset_id,))
    return row["hostname"] if row else None


def _email_lists(conn: sqlite3.Connection, event_id: str) -> dict[str, Any]:
    recipients = [
        _user(conn, "email", r["recipient_user_id"]) or r["recipient_unresolved"]
        for r in _rows(
            conn,
            "SELECT recipient_user_id, recipient_unresolved FROM email_recipients WHERE event_id = ? ORDER BY position",
            (event_id,),
        )
    ]
    attachments = []
    for a in _rows(
        conn,
        "SELECT position, file_name, sha256, size FROM email_attachments WHERE event_id = ? ORDER BY position",
        (event_id,),
    ):
        item: dict[str, Any] = {"name": a["file_name"], "sha256": a["sha256"], "size": a["size"]}
        contains = _rows(
            conn,
            "SELECT file_name AS name, sha256 FROM email_attachment_contents WHERE event_id = ? "
            "AND attachment_position = ? ORDER BY position",
            (event_id, a["position"]),
        )
        if contains:
            item["contains"] = contains
        attachments.append(item)
    urls = [
        r["url"] for r in _rows(conn, "SELECT url FROM email_urls WHERE event_id = ? ORDER BY position", (event_id,))
    ]
    return {"recipients": recipients, "attachments": attachments, "urls": urls}


def _special(conn: sqlite3.Connection, source: str, event_id: str, detail: dict[str, Any]) -> dict[str, Any]:
    if source == "email":
        return _email_lists(conn, event_id)
    if source == "email_clicks":
        row = _one(conn, "SELECT message_id FROM email_logs WHERE event_id = ?", (detail["email_event_id"],))
        return {"message_id": row["message_id"] if row else None}
    if source == "firewall":
        return {"zone_src": detail["src_zone_id"], "zone_dst": detail["dst_zone_id"] or detail["dst_zone_unresolved"]}
    if source == "ai_gateway":
        calls = _rows(
            conn,
            "SELECT name, arguments_json, result FROM ai_tool_calls WHERE event_id = ? ORDER BY position",
            (event_id,),
        )
        return {
            "tool_calls": [
                {"name": c["name"], "args": json.loads(c["arguments_json"]), "result": c["result"]} for c in calls
            ]
        }
    return {}


def log_record(conn: sqlite3.Connection, event_id: str) -> tuple[str, dict[str, Any]] | None:
    """(source, raw event) for a stored event, or None if the event is not in the database."""
    hub = _one(conn, "SELECT source, timestamp FROM logs WHERE event_id = ?", (event_id,))
    if hub is None:
        return None
    source = hub["source"]
    spec = SPECS[source]
    # spec.table comes from the trusted SPECS constant, never from input.
    detail = _one(conn, f"SELECT * FROM {spec.table} WHERE event_id = ?", (event_id,))  # noqa: S608
    if detail is None:
        return None
    event: dict[str, Any] = {"event_id": event_id, "timestamp": hub["timestamp"]}
    for original, column in spec.direct.items():
        event[original] = _value(column, detail.get(column))
    for original, column, fallback in spec.users:
        event[original] = _user(conn, source, detail.get(column)) or (detail.get(fallback) if fallback else None)
    for original, column in spec.assets.items():
        event[original] = _host(conn, detail.get(column))
    for original, mapping in spec.nested.items():
        event[original] = {key: _value(column, detail.get(column)) for key, column in mapping.items()}
    event.update(_special(conn, source, event_id, detail))
    if source in CSV_SOURCES:
        event = {k: "" if v is None else str(v) for k, v in event.items()}
    return source, event


def alert_records(conn: sqlite3.Connection, alert_id: str) -> list[tuple[str, dict[str, Any]]]:
    """Raw events cited by an alert, in citation order (events missing from the database are skipped)."""
    ids = [
        r[0]
        for r in conn.execute("SELECT event_id FROM alert_events WHERE alert_id = ? ORDER BY position", (alert_id,))
    ]
    return [rec for eid in ids if (rec := log_record(conn, eid)) is not None]
