"""Verify schema, field coverage, source/detail consistency and stored data."""

import hashlib
import json
import re
import sqlite3

from .core import Sources, Writer
from .logs import SPECS
from .schema import MODEL_PATH, identifier

SEARCH_FIELDS = {
    "src_ip",
    "dst_ip",
    "assigned_ip",
    "sender_ip",
    "sha256",
    "domain",
    "url",
    "query",
    "customer_id",
    "session_id",
    "build_id",
    "identity_name",
    "access_key_id",
}


def create_indexes(connection: sqlite3.Connection, writer: Writer) -> None:
    model = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    desired = {
        ("logs", ("source", "timestamp")),
        ("logs", ("timestamp",)),
        ("alerts", ("created_at",)),
        ("alerts", ("rule_id", "created_at")),
        ("threat_intelligence", ("indicator_type", "value")),
    }
    for edge in model["relations"]:
        if edge["kind"] == "fk":
            desired.add((edge["child"], tuple(edge["childFields"])))
    for table, columns in writer.columns.items():
        desired.update((table, (name,)) for name, kind in columns if name in SEARCH_FIELDS)
    existing = {}
    for table in writer.columns:
        info = connection.execute(f"PRAGMA table_info({identifier(table)})").fetchall()  # noqa: S608
        keys = [tuple(r[1] for r in sorted(info, key=lambda r: r[5]) if r[5])]
        for index in connection.execute(f"PRAGMA index_list({identifier(table)})"):  # noqa: S608
            keys.append(tuple(r[2] for r in connection.execute(f"PRAGMA index_info({identifier(index[1])})")))  # noqa: S608
        existing[table] = keys
    for table, columns in sorted(desired, key=lambda item: (item[0], -len(item[1]), item[1])):
        if any(key[: len(columns)] == columns for key in existing[table]):
            continue
        name = identifier("idx_" + table + "_" + "_".join(columns))
        fields = ", ".join(map(identifier, columns))
        connection.execute(f"CREATE INDEX {name} ON {identifier(table)} ({fields})")  # noqa: S608
        existing[table].append(columns)
    connection.execute("ANALYZE")
    connection.commit()


def schema_contract(connection: sqlite3.Connection) -> dict:
    model = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    actual = {
        r[0]
        for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    }
    expected = {t["name"] for t in model["tables"]}
    if actual != expected:
        raise ValueError(f"Schema tables differ from the approved model: {actual ^ expected}")
    for table in model["tables"]:
        info = connection.execute(f"PRAGMA table_info({identifier(table['name'])})").fetchall()  # noqa: S608
        if [r[1] for r in info] != [f["name"] for f in table["fields"]]:
            raise ValueError(f"Column mismatch in {table['name']}")
        if [r[1] for r in sorted(info, key=lambda r: r[5]) if r[5]] != table["pk"]:
            raise ValueError(f"Primary key mismatch in {table['name']}")
    return model


def counts_and_distinct(connection: sqlite3.Connection, writer: Writer, model: dict) -> tuple[dict, dict]:
    counts, distinct = {}, {}
    for table in model["tables"]:
        name = table["name"]
        count = connection.execute(f"SELECT COUNT(*) FROM {identifier(name)}").fetchone()[0]  # noqa: S608
        if count != writer.counts[name]:
            raise ValueError(f"Lost rows in {name}: wrote {writer.counts[name]}, found {count}")
        counts[name] = count
        distinct[name] = {}
        for field in table["fields"]:
            column = identifier(field["name"])
            expression = (
                f"CASE WHEN {column} NOT IN ('{{}}','[]') THEN {column} END"
                if field["name"].endswith("_json")
                else column
            )
            observed = connection.execute(f"SELECT COUNT(DISTINCT {expression}) FROM {identifier(name)}").fetchone()[0]  # noqa: S608
            distinct[name][field["name"]] = observed
            expected = re.fullmatch(r"(\d+)(?: previstos)?", field["distinct"])
            if expected and observed != int(expected[1]):
                raise ValueError(
                    f"Distinct-value mismatch in {name}.{field['name']}: expected {expected[1]}, got {observed}"
                )
    if counts["alert_history"]:
        raise ValueError("Source ingestion must not manufacture triage results")
    return counts, distinct


def validate_sources(connection: sqlite3.Connection, sources: Sources) -> None:
    for source, spec in SPECS.items():
        table = identifier(spec.table)
        missing = connection.execute(
            f"SELECT COUNT(*) FROM logs l LEFT JOIN {table} d USING(event_id) WHERE l.source=? AND d.event_id IS NULL",  # noqa: S608
            (source,),
        ).fetchone()[0]
        wrong = connection.execute(
            f"SELECT COUNT(*) FROM {table} d JOIN logs l USING(event_id) WHERE l.source<>?",  # noqa: S608
            (source,),
        ).fetchone()[0]
        if missing or wrong:
            raise ValueError(f"Source/detail mismatch for {source}")
    for key, expected in sources.manifest.items():
        derived = key.startswith("implementation_docs/")
        path = (sources.relations if derived else sources.data) / key.split("/", 1)[1]
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected["sha256"]:
            raise ValueError(f"Input changed during ingestion: {key}")


def validate(connection: sqlite3.Connection, sources: Sources, writer: Writer) -> dict:
    model = schema_contract(connection)
    integrity = connection.execute("PRAGMA integrity_check").fetchall()
    if integrity != [("ok",)]:
        raise ValueError(f"SQLite integrity_check failed: {integrity[:5]}")
    violations = connection.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise ValueError(f"Foreign key violations: {violations[:5]}")
    counts, distinct = counts_and_distinct(connection, writer, model)
    validate_sources(connection, sources)
    return {
        "integrity_check": "ok",
        "foreign_key_violations": 0,
        "source_detail_check": "ok",
        "inputs_unchanged": True,
        "table_count": len(counts),
        "row_counts": counts,
        "distinct_values": distinct,
    }
