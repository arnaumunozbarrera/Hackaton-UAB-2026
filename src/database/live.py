"""Create a "live" copy of the database: inventory, intelligence and log corpus, but no alerts.

Why: `build` loads every alert of docs/, and the simulated SOC API serves the same alerts, so a sync finds nothing
new. For a real-time demo the live copy starts empty of alerts; `serve --live N` then pulls them from the API in
chronological order (a few per tick), ingests each alert with its cited events and triages it.

    python -m src.database.live [--source data/tarvia.sqlite] [--out data/tarvia_live.sqlite] [--replace]
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

from .schema import ROOT

# Every table that holds alerts or results derived from them (children first).
ALERT_TABLES = (
    "severity_evidence", "severity_assessments",
    "alert_incidents", "alert_embeddings", "triage_tickets", "alert_log_selection", "alert_dedup", "alert_enriched",
    "alert_history", "alert_users", "alert_assets", "alert_indicators", "alert_files", "alert_processes",
    "alert_customers", "alert_cloud", "alert_ai_sessions", "alert_events", "alerts",
)  # fmt: skip


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
    args = parser.parse_args()
    removed = create_live(args.source, args.out, args.replace)
    print(f"Live database ready: {args.out} (alerts removed: {removed.get('alerts', 0)}; logs and inventory kept)")


if __name__ == "__main__":
    main()
