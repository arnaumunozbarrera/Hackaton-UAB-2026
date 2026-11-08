"""Create a "live" copy of the database: inventory, intelligence and log corpus, but no alerts.

Why: `build` loads every alert of docs/, and the simulated SOC API serves the same alerts, so a sync finds nothing
new. For a real-time demo the live copy starts empty of alerts; `serve --live N` then pulls them from the API in
chronological order (a few per tick), ingests each alert with its cited events and triages it.

    python -m src.database.live [--source data/tarvia.sqlite] [--out data/tarvia_live.sqlite] [--replace]
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from .schema import ROOT

# Every table that holds alerts or results derived from them (children first).
ALERT_TABLES = (
    "attack_chains", "alert_incidents", "alert_embeddings", "triage_tickets", "alert_log_selection", "alert_dedup", "alert_enriched",
    "alert_history", "alert_users", "alert_assets", "alert_indicators", "alert_files", "alert_processes",
    "alert_customers", "alert_cloud", "alert_ai_sessions", "alert_events", "alerts",
)  # fmt: skip


RAW_ALERT_TABLES = (
    "alert_users", "alert_assets", "alert_indicators", "alert_files", "alert_processes", "alert_customers",
    "alert_cloud", "alert_ai_sessions", "alert_events", "alerts",
)  # fmt: skip
# Pipeline results (src/database/pipeline.sql): recomputed for the kept alerts.
RESULT_TABLES = ("soc_actions", "soc_notifications", "ticket_automation", "alert_received")


def read_alert_ids(path: Path) -> list[str]:
    """alert_id of every line of a JSONL alerts file (same format as docs/03_alertas/alertas.jsonl)."""
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line)["alert_id"] for line in fh if line.strip()]


def create_demo(source: Path, out: Path, keep: list[str], replace: bool = False, label: str = "") -> dict[str, int]:
    """Copy keeping only the `keep` alerts with their raw data; every derived table is emptied for recomputation.

    The copy is marked `filter_scope = database`: the triage flow then recomputes the informative-log selection over
    these alerts only (a log set aside before because other alerts also cited it can become informative).
    """
    if not source.exists():
        raise FileNotFoundError(f"Source database not found: {source}. Run python -m src.database.build first")
    if out.exists() and not replace:
        raise FileExistsError(f"{out} exists; use --replace to recreate it")
    marks = ",".join("?" * len(keep))
    src_ro = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    try:
        query = f"SELECT alert_id FROM alerts WHERE alert_id IN ({marks})"  # noqa: S608 - only '?' placeholders
        found = {r[0] for r in src_ro.execute(query, keep)}
    finally:
        src_ro.close()
    missing = sorted(set(keep) - found)
    if missing:
        raise ValueError(f"{len(missing)} alert(s) not in {source}: {', '.join(missing[:10])}")
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    src, dst = sqlite3.connect(source), sqlite3.connect(out)
    try:
        src.backup(dst)
        tables = {r[0] for r in dst.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        dst.execute("PRAGMA foreign_keys=OFF")
        dst.execute("CREATE TEMP TABLE keep_ids (alert_id TEXT PRIMARY KEY)")
        dst.executemany("INSERT OR IGNORE INTO keep_ids VALUES (?)", [(a,) for a in keep])
        removed = {}
        for table in ALERT_TABLES + RESULT_TABLES:
            if table not in tables:
                continue
            if table in RAW_ALERT_TABLES:
                sql = f'DELETE FROM "{table}" WHERE alert_id NOT IN (SELECT alert_id FROM keep_ids)'  # noqa: S608
            else:
                sql = f'DELETE FROM "{table}"'  # noqa: S608 - fixed table names
            removed[table] = dst.execute(sql).rowcount
        dst.execute("CREATE TABLE IF NOT EXISTS pipeline_meta (key TEXT PRIMARY KEY, value TEXT)")
        dst.executemany("INSERT OR REPLACE INTO pipeline_meta VALUES (?, ?)",
                        [("filter_scope", "database"), ("alerts_file", label), ("alerts_kept", str(len(found)))])  # fmt: skip
        dst.commit()  # no VACUUM: the log corpus dominates the size and VACUUM rewrites the whole file
        return removed
    finally:
        src.close()
        dst.close()


def create_live(source: Path, out: Path, replace: bool = False) -> dict[str, int]:
    if not source.exists():
        raise FileNotFoundError(f"Source database not found: {source}. Run python -m src.database.build first")
    if out.exists() and not replace:
        raise FileExistsError(f"{out} exists; use --replace to recreate it")
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    src, dst = sqlite3.connect(source), sqlite3.connect(out)
    try:
        src.backup(dst)
        tables = {r[0] for r in dst.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        dst.execute("PRAGMA foreign_keys=OFF")
        removed = {}
        for table in ALERT_TABLES:
            if table in tables:
                removed[table] = dst.execute(f'DELETE FROM "{table}"').rowcount  # noqa: S608 - fixed table names
        dst.commit()
        dst.execute("VACUUM")
        return removed
    finally:
        src.close()
        dst.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, default=ROOT / "data" / "tarvia.sqlite")
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "tarvia_live.sqlite")
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--keep-file", type=Path, help="JSONL alerts file: keep only these alerts (demo database)")
    args = parser.parse_args()
    if args.keep_file:
        ids = read_alert_ids(args.keep_file)
        removed = create_demo(args.source, args.out, ids, args.replace, args.keep_file.name)
        print(f"Demo database ready: {args.out} ({len(ids)} alerts kept from {args.keep_file.name}; "
              f"{removed.get('alerts', 0)} removed; derived tables emptied for recomputation)")  # fmt: skip
        return
    removed = create_live(args.source, args.out, args.replace)
    print(f"Live database ready: {args.out} (alerts removed: {removed.get('alerts', 0)}; logs and inventory kept)")


if __name__ == "__main__":
    main()
