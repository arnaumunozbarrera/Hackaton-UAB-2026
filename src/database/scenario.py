"""Demo scenario: checkpoints of the database and the arrival of a new batch of alerts.

Why: for a demo the UI must show only a new batch of alerts as pending, without losing what the database holds,
and it must be possible to return exactly to the moment before the batch arrived.

    python -m src.database.scenario prepare --alerts data/demo_alertas_comunes.jsonl
    python -m src.database.scenario list
    python -m src.database.scenario restore baseline-demo_alertas_comunes   (stop the server first)
    python -m src.database.scenario checkpoint NAME

`prepare`:
1. checkpoint `before-<file>` of the untouched database;
2. removes the incoming alerts already stored, with everything derived from them (in the scenario they have not
   arrived yet; their log events stay, they are part of the corpus);
3. closes the backlog: every alert in the database is recorded in `backlog_closed`, so it no longer appears as
   pending. Nothing is invented: tickets keep their real content and no verdict or decision is written;
4. marks the database `filter_scope = database` (the informative-log selection of the new alerts is computed
   over the alerts actually received, not over the whole dataset);
5. checkpoint `baseline-<file>`: backlog processed, new batch not received. Restore it to rerun the demo.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .schema import ROOT

CHECKPOINTS = ROOT / "data" / "checkpoints"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _copy(source: Path, target: Path) -> None:
    """Consistent copy with the SQLite backup API (safe while other connections read the source)."""
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    dst = sqlite3.connect(target)
    try:
        src.backup(dst)
    finally:
        src.close()
        dst.close()


def _counts(db: Path) -> dict[str, int]:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        one = lambda sql: conn.execute(sql).fetchone()[0]  # noqa: E731
        out = {"alerts": one("SELECT COUNT(*) FROM alerts")}
        try:
            out["pending_tickets"] = one(
                "SELECT COUNT(*) FROM triage_tickets WHERE decision IS NULL AND route = 'llm' "
                "AND alert_id NOT IN (SELECT alert_id FROM backlog_closed)"
            )
            out["backlog_closed"] = one("SELECT COUNT(*) FROM backlog_closed")
        except sqlite3.OperationalError:
            pass
        return out
    finally:
        conn.close()


def checkpoint(db: Path, name: str, note: str = "") -> Path:
    CHECKPOINTS.mkdir(parents=True, exist_ok=True)
    target = CHECKPOINTS / f"{name}.sqlite"
    if target.exists():
        raise FileExistsError(f"checkpoint {name} exists: choose another name")
    _copy(db, target)
    manifest = {"name": name, "database": str(db), "created_at": now(), "note": note} | _counts(target)
    target.with_suffix(".json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


def restore(db: Path, name: str) -> dict:
    """Overwrite `db` with checkpoint `name` (backup API: no file is deleted). Stop the server first."""
    source = CHECKPOINTS / f"{name}.sqlite"
    if not source.exists():
        raise FileNotFoundError(f"checkpoint not found: {source}")
    _copy(source, db)
    return _counts(db)


def list_checkpoints() -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(CHECKPOINTS.glob("*.json"))]


def _alert_tables(conn: sqlite3.Connection) -> list[str]:
    names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
    return [n for n in names if any(c[1] == "alert_id" for c in conn.execute(f'PRAGMA table_info("{n}")'))]


def prepare(db: Path, alerts_file: Path) -> dict:
    with alerts_file.open(encoding="utf-8") as fh:
        incoming = [json.loads(line)["alert_id"] for line in fh if line.strip()]
    stem = alerts_file.stem
    before = checkpoint(db, f"before-{stem}", f"database untouched, before preparing {alerts_file.name}")
    conn = sqlite3.connect(db)
    try:
        conn.executescript((Path(__file__).with_name("pipeline.sql")).read_text(encoding="utf-8"))
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("CREATE TEMP TABLE incoming (alert_id TEXT PRIMARY KEY)")
        conn.executemany("INSERT OR IGNORE INTO incoming VALUES (?)", [(a,) for a in incoming])
        present = [r[0] for r in conn.execute("SELECT alert_id FROM alerts WHERE alert_id IN (SELECT * FROM incoming)")]
        removed = {}
        # Evidence has no alert_id: remove children before the generic loop deletes their assessments.
        n = conn.execute(
            "DELETE FROM severity_evidence WHERE assessment_id IN "
            "(SELECT assessment_id FROM severity_assessments WHERE alert_id IN (SELECT alert_id FROM incoming))"
        ).rowcount
        if n:
            removed["severity_evidence"] = n
        for table in _alert_tables(conn):
            n = conn.execute(f'DELETE FROM "{table}" WHERE alert_id IN (SELECT alert_id FROM incoming)').rowcount  # noqa: S608
            if n:
                removed[table] = n
        closed = conn.execute(
            "INSERT OR IGNORE INTO backlog_closed (alert_id, closed_at, reason) SELECT alert_id, ?, ? FROM alerts",
            (now(), f"backlog closed before receiving {alerts_file.name}"),
        ).rowcount
        conn.execute("CREATE TABLE IF NOT EXISTS pipeline_meta (key TEXT PRIMARY KEY, value TEXT)")
        conn.executemany(
            "INSERT OR REPLACE INTO pipeline_meta VALUES (?, ?)",
            [
                ("filter_scope", "database"),
                ("scenario_alerts_file", alerts_file.name),
                ("scenario_prepared_at", now()),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    base = checkpoint(db, f"baseline-{stem}", f"backlog processed, {alerts_file.name} not received yet")
    return {"incoming": len(incoming), "already_stored_removed": present, "rows_removed": removed,
            "backlog_closed": closed, "checkpoints": [before.stem, base.stem]} | _counts(db)  # fmt: skip


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", type=Path, default=ROOT / "data" / "tarvia_live.sqlite")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--alerts", type=Path, default=ROOT / "data" / "demo_alertas_comunes.jsonl")
    sub.add_parser("list")
    for cmd in ("checkpoint", "restore"):
        sub.add_parser(cmd).add_argument("name")
    args = parser.parse_args()
    if args.cmd == "prepare":
        print(json.dumps(prepare(args.db, args.alerts), ensure_ascii=False, indent=2))
    elif args.cmd == "checkpoint":
        print(f"checkpoint written: {checkpoint(args.db, args.name)}")
    elif args.cmd == "restore":
        print(f"restored {args.name} into {args.db}: {restore(args.db, args.name)}")
    else:
        for m in list_checkpoints():
            print(f"{m['name']:<40} {m['created_at']}  alerts={m.get('alerts')}  pending={m.get('pending_tickets', '-')}"
                  f"  closed={m.get('backlog_closed', '-')}  {m.get('note', '')}")  # fmt: skip


if __name__ == "__main__":
    main()
