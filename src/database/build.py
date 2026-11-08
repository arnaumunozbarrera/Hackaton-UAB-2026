"""Build and validate the agreed database, publishing it only after success."""

import argparse
import json
import os
import sqlite3
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from .alerts import load_alerts
from .core import Sources, Writer
from .intelligence import load_intelligence
from .inventory import load_inventory
from .logs import load_logs
from .schema import ROOT, SCHEMA_PATH
from .validation import create_indexes, validate


def destinations(output: Path, report: Path, data: Path, *, replace: bool) -> None:
    for target in [output, report]:
        if target == data or data in target.parents:
            raise ValueError("The source data directory is read-only; choose another output location")
    if output == report or output.suffix not in {".sqlite", ".sqlite3", ".db"}:
        raise ValueError("Use a SQLite extension and a separate report path")
    if output.exists() and not replace:
        raise FileExistsError(f"Database already exists: {output}. Use --replace only to intentionally rebuild it.")


def ingest(connection: sqlite3.Connection, sources: Sources, progress: Callable[[str], None]) -> tuple[Writer, list]:
    writer = Writer(connection)
    issues = []
    progress("Loading context and approved relations...")
    directory, rules = load_inventory(writer, sources)
    writer.flush_all()
    connection.commit()
    progress("Loading local intelligence and sandbox...")
    load_intelligence(writer, sources, issues)
    writer.flush_all()
    connection.commit()
    progress("Loading 18 log sources...")
    load_logs(writer, sources, directory, progress)
    progress("Loading alerts and their entity/event relations...")
    load_alerts(writer, sources, directory, rules)
    writer.flush_all()
    connection.commit()
    return writer, issues


def build_database(
    output: Path,
    data: Path = ROOT / "docs",
    relations: Path = ROOT / "implementation_docs",
    report: Path | None = None,
    *,
    replace: bool = False,
    progress: Callable[[str], None] = print,
) -> dict:
    output, data, relations = output.resolve(), data.resolve(), relations.resolve()
    report = report.resolve() if report else output.with_suffix(".ingestion.json")
    destinations(output, report, data, replace=replace)
    output.parent.mkdir(parents=True, exist_ok=True)
    report.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix="." + output.stem + ".building-", suffix=".sqlite", dir=output.parent
    )
    os.close(handle)
    temporary = Path(temporary_name)
    connection = sqlite3.connect(temporary)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        sources = Sources(data, relations)
        writer, issues = ingest(connection, sources, progress)
        progress("Creating indexes and verifying every documented distinct-value count...")
        create_indexes(connection, writer)
        checks = validate(connection, sources, writer)
        result = {
            "database": str(output),
            "completed_at_utc": datetime.now(timezone.utc).isoformat(),
            "validation": checks,
            "source_files": sources.manifest,
            "source_issues": issues,
        }
        connection.close()
        connection = None
        os.replace(temporary, output)
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        progress(f"Database ready: {output}")
        return result
    finally:
        if connection is not None:
            connection.close()
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "tarvia.sqlite")
    parser.add_argument("--data", type=Path, default=ROOT / "docs")
    parser.add_argument("--relations", type=Path, default=ROOT / "implementation_docs")
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--replace", action="store_true", help="Intentionally replace an existing database after validation"
    )
    args = parser.parse_args()
    build_database(args.out, args.data, args.relations, args.report, replace=args.replace)


if __name__ == "__main__":
    main()
