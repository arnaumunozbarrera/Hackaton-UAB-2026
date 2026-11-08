"""Shared strict conversion and batched inserts for loss-aware ingestion."""

import csv
import hashlib
import json
import math
import sqlite3
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from .schema import BOOLEAN_FIELDS, DETAIL_SOURCES, identifier


def empty(value: object) -> bool:
    return value is None or isinstance(value, str) and value == ""


def timestamp(value: str, *, local: bool = False) -> str:
    """Convert explicit instants to UTC; leave calendar dates to their own columns."""
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if local:
        if moment.tzinfo is not None:
            raise ValueError("Change calendar must contain local, naive times")
        moment = moment.replace(tzinfo=ZoneInfo("Europe/Madrid"))
    elif moment.tzinfo is None:
        raise ValueError("An event timestamp must specify its timezone")
    moment = moment.astimezone(timezone.utc)
    precision = "microseconds" if moment.microsecond % 1000 else "milliseconds"
    return moment.isoformat(timespec=precision).replace("+00:00", "Z")


def fields(row: dict, allowed: set[str], location: str) -> None:
    unexpected = set(row) - allowed
    if unexpected:
        raise ValueError(f"Unmapped fields in {location}: {sorted(unexpected)}")


def convert(name: str, kind: str, value: object) -> object:
    if value is None:
        return None
    if name.endswith("_json"):
        if not isinstance(value, dict):
            raise ValueError(f"{name} must contain an object")
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if empty(value):
        return None
    if name in BOOLEAN_FIELDS:
        if value in (True, False, 0, 1):
            return int(value)
        boolean = {"true": 1, "false": 0, "1": 1, "0": 0}.get(str(value).lower())
        if boolean is None:
            raise ValueError(f"Invalid boolean for {name}")
        return boolean
    if kind == "INTEGER":
        number = int(value)
        if isinstance(value, float) and value != number:
            raise ValueError(f"Fractional value for integer {name}")
        return number
    if kind == "REAL":
        number = float(value)
        if not math.isfinite(number):
            raise ValueError(f"Non-finite value for {name}")
        return number
    if not isinstance(value, str):
        raise ValueError(f"Expected text for {name}, got {type(value).__name__}")
    return value


class Sources:
    """Read original inputs and record external provenance without duplicating DB data."""

    def __init__(self, data: Path, relations: Path):
        self.data = data
        self.relations = relations
        self.manifest: dict[str, dict] = {}

    def document(self, relative: str) -> str:
        raw = (self.data / relative).read_bytes()
        self.manifest["docs/" + relative] = {"documents": 1, "sha256": hashlib.sha256(raw).hexdigest()}
        return raw.decode("utf-8")

    def records(self, relative: str, *, derived: bool = False) -> Iterator[dict]:
        path = (self.relations if derived else self.data) / relative
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        count = 0
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = (
                csv.DictReader(stream)
                if path.suffix == ".csv"
                else (json.loads(line) for line in stream if line.strip())
            )
            for row in reader:
                count += 1
                yield row
        key = ("implementation_docs/" if derived else "docs/") + relative
        self.manifest[key] = {"rows": count, "sha256": digest.hexdigest()}


class Writer:
    """Parameterize values and reject fields that do not exist in the agreed schema."""

    def __init__(self, connection: sqlite3.Connection, batch_size: int = 2000):
        self.connection = connection
        self.batch_size = batch_size
        self.columns: dict[str, list[tuple[str, str]]] = {}
        self.buffers: dict[str, list[tuple]] = {}
        self.statements: dict[str, str] = {}
        self.counts: dict[str, int] = {}
        for (table,) in connection.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            info = connection.execute(f"PRAGMA table_info({identifier(table)})").fetchall()  # noqa: S608
            columns = [(row[1], row[2]) for row in info]
            names = ",".join(identifier(name) for name, kind in columns)
            self.columns[table] = columns
            self.buffers[table] = []
            self.counts[table] = 0
            placeholders = ",".join("?" for column in columns)
            self.statements[table] = f"INSERT INTO {identifier(table)} ({names}) VALUES ({placeholders})"  # noqa: S608

    def add(self, table: str, row: dict) -> None:
        columns = self.columns[table]
        unexpected = set(row) - {name for name, kind in columns}
        if unexpected:
            raise ValueError(f"Unmapped destination fields in {table}: {sorted(unexpected)}")
        values = tuple(convert(name, kind, row.get(name)) for name, kind in columns)
        self.buffers[table].append(values)
        self.counts[table] += 1
        if len(self.buffers[table]) >= self.batch_size:
            self.flush(table)

    def flush(self, table: str) -> None:
        if table in DETAIL_SOURCES:
            self.flush("logs")
        if self.buffers[table]:
            self.connection.executemany(self.statements[table], self.buffers[table])
            self.buffers[table].clear()

    def flush_all(self) -> None:
        for table in self.buffers:
            self.flush(table)


class Directory:
    """Resolve only directory-backed identities; never strip arbitrary domains."""

    def __init__(self, users: list[dict], assets: list[dict]):
        self.user_rows = {row["user_id"]: row for row in users}
        self.asset_rows = {row["asset_id"]: row for row in assets}
        self.upns = self._index(users, "upn", "user_id", insensitive=True)
        self.usernames = self._index(users, "username", "user_id", insensitive=True)
        self.hosts = self._index(assets, "hostname", "asset_id")
        self.messages: dict[str, str] = {}
        self.zones: set[str] = set()

    @staticmethod
    def _index(rows: list[dict], key: str, target: str, *, insensitive: bool = False) -> dict[str, str]:
        result = {}
        for row in rows:
            value = row[key].casefold() if insensitive else row[key]
            if value in result:
                raise ValueError(f"Duplicate directory key: {key}")
            result[value] = row[target]
        return result

    def user(self, value: str | None) -> str | None:
        if empty(value):
            return None
        if "@" in value:
            return self.upns.get(value.casefold())
        if "\\" in value:
            domain, value = value.split("\\", 1)
            if domain.casefold() != "tarvia":
                return None
        return self.usernames.get(value.casefold())

    def require_user(self, value: str | None) -> str | None:
        resolved = self.user(value)
        if not empty(value) and resolved is None:
            raise ValueError("An inventory user reference cannot be resolved")
        return resolved

    def asset(self, value: str | None) -> str | None:
        resolved = self.hosts.get(value)
        if not empty(value) and resolved is None:
            raise ValueError("An asset reference cannot be resolved")
        return resolved

    def observed_user(self, value: str | None, name: str = "user_id", fallback: str | None = None) -> dict:
        resolved = self.user(value)
        result = {name: resolved}
        if fallback:
            result[fallback] = value if not empty(value) and resolved is None else None
        elif not empty(value) and resolved is None:
            raise ValueError("An observed account needs a fallback column to preserve its value")
        return result
