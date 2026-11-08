"""Persist the informative-log selection of `log_noise_discard` per alert in `alert_log_selection`.

Why: the filter needs the whole dataset for its cross-alert stages (N2, N3) and takes several seconds, so it runs
once and its decision is stored. Alerts the filter does not know (ingested later from the API with events it never
saw) are stored as `unfiltered`: their cited logs are all treated as informative, never silently dropped.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def alerts_without_selection(conn: sqlite3.Connection) -> list[str]:
    return [
        r[0]
        for r in conn.execute(
            "SELECT alert_id FROM alerts WHERE alert_id NOT IN (SELECT DISTINCT alert_id FROM alert_log_selection) "
            "ORDER BY alert_id"
        )
    ]


def _row(fr: Any, alert_id: str, eid: str, known: bool, fallback: tuple[str, str] | None) -> tuple:
    record = fr.kept.get(eid) or fr.discarded_records.get(eid) if known else None
    source, ts = (record.source, str(record.event.get("timestamp", ""))) if record else (fallback or (None, None))
    if not known or record is None:
        return (alert_id, eid, source, ts, "unfiltered", "not seen by the filter", None)
    if eid in fr.kept:
        if eid in fr.open_text_kept:
            exp = fr.open_text_kept[eid]
            return (alert_id, eid, source, ts, "kept", f"open_text:{exp.category}", exp.reference)
        if eid in fr.guarded:
            return (alert_id, eid, source, ts, "kept", f"guard:{fr.guarded[eid]}", None)
        return (alert_id, eid, source, ts, "kept", "unexplained", None)
    stage = fr.discarded[eid]
    if stage == "N4" and eid in fr.explanations:
        exp = fr.explanations[eid]
        return (alert_id, eid, source, ts, "N4", f"explained:{exp.category}", exp.reference)
    return (alert_id, eid, source, ts, stage, None, None)


def persist_selection(conn: sqlite3.Connection, fr: Any, alert_ids: Iterable[str] | None = None) -> dict[str, int]:
    """Write the selection of the given alerts (default: those without one). Returns counts per state."""
    ids = list(alert_ids) if alert_ids is not None else alerts_without_selection(conn)
    counts: dict[str, int] = {}
    for aid in ids:
        cited = conn.execute(
            "SELECT e.event_id, d.source, d.timestamp FROM alert_events e LEFT JOIN dim_log d ON d.event_id = e.event_id "
            "WHERE e.alert_id = ? AND e.event_id IS NOT NULL ORDER BY e.position",
            (aid,),
        ).fetchall()
        known = aid in fr.alert_events
        conn.execute("DELETE FROM alert_log_selection WHERE alert_id = ?", (aid,))
        rows = {eid: _row(fr, aid, eid, known, (src, ts)) for eid, src, ts in cited}
        conn.executemany("INSERT INTO alert_log_selection VALUES (?, ?, ?, ?, ?, ?, ?)", list(rows.values()))
        for row in rows.values():
            counts[row[4]] = counts.get(row[4], 0) + 1
    conn.commit()
    return counts


def run_and_persist(conn: sqlite3.Connection, data_dir: str | Path = "docs", force: bool = False) -> dict[str, int]:
    """Run the filter only if some alert lacks a selection (or `force`), then persist."""
    pending = None if force else alerts_without_selection(conn)
    if pending == []:
        return {}
    from ..log_noise_discard import run_filter

    fr = run_filter(data_dir)
    target = [r[0] for r in conn.execute("SELECT alert_id FROM alerts ORDER BY alert_id")] if force else pending
    return persist_selection(conn, fr, target)
