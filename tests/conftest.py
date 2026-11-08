"""Shared fixtures: a context-only database and the 20 debug alerts replayed through a fake SOC API.

`ReplayApi` serves dev/alertas_debug.jsonl and the raw log rows in dev/alertas_debug_events.jsonl with the same
methods as `src.soc_api.SocApi`, so ingestion, checks, prompts and the workflow run end to end without network.
"""

import json
import shutil
import sqlite3
import uuid
from pathlib import Path

import pytest

from src.database import build
from src.database.schema import ROOT
from src.database.sync import AlertIngestor

DEBUG_ALERTS = ROOT / "dev" / "alertas_debug.jsonl"
DEBUG_EVENTS = ROOT / "dev" / "alertas_debug_events.jsonl"


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


class ReplayApi:
    """In-process stand-in for the mock SOC API (alerts, log lookup, approvals and containment)."""

    def __init__(self, alerts: list[dict] | None = None):
        self.alert_list = read_jsonl(DEBUG_ALERTS) if alerts is None else alerts
        self.events = {(e["source"], e["row"]["event_id"]): e["row"] for e in read_jsonl(DEBUG_EVENTS)}
        self.approvals: dict[str, dict] = {}
        self.containment: list[dict] = []

    def alerts(self, status: str = "new", page_size: int = 500):
        yield from (a for a in self.alert_list if a.get("status") == status)

    def find_event(self, source: str, event_id: str) -> dict | None:
        return self.events.get((source, event_id))

    def find_log(self, source: str, key: str, value: str) -> dict | None:
        return next((row for (s, _), row in self.events.items() if s == source and row.get(key) == value), None)

    def search_logs(self, source: str, q: str, limit: int = 2000) -> list[dict]:
        needle = q.lower()
        hits = [
            r
            for (s, _), r in self.events.items()
            if s == source and needle in json.dumps(r, ensure_ascii=False).lower()
        ]
        return hits[:limit]

    def approve(self, action: str, target: str, approver: str, reason: str = "") -> dict:
        token = "APR-" + uuid.uuid4().hex[:10]
        self.approvals[token] = {"action": action, "target": target, "approver": approver, "reason": reason}
        return {"approval_token": token, **self.approvals[token]}

    def contain(self, action: str, target: str, justification: str, approval_token: str = "", ticket_id: str = ""):
        if action not in {"block_ioc", "purge_email"}:
            approval = self.approvals.get(approval_token)
            if not approval or approval["action"] != action or approval["target"] != target:
                raise PermissionError("falta aprobación humana válida para esta acción y objetivo")
        record = {"action": action, "target": target, "approval_token": approval_token, "result": "ok (simulado)"}
        self.containment.append(record)
        return record


@pytest.fixture(scope="session")
def context_db_path(tmp_path_factory) -> Path:
    path = tmp_path_factory.mktemp("context") / "context.sqlite"
    build.build_database(path, context_only=True, progress=lambda message: None)
    return path


@pytest.fixture(scope="session")
def ingested_db_path(context_db_path, tmp_path_factory) -> Path:
    """Context-only DB with the 20 debug alerts and their logs stored (no triage results)."""
    path = tmp_path_factory.mktemp("ingested") / "ingested.sqlite"
    shutil.copy(context_db_path, path)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys=ON")
    ingestor = AlertIngestor(connection, ReplayApi())
    for alert in read_jsonl(DEBUG_ALERTS):
        ingestor.ingest(alert)
    connection.close()
    return path


@pytest.fixture
def mini_db(ingested_db_path, tmp_path) -> Path:
    """A private, writable copy of the ingested debug database."""
    path = tmp_path / "tarvia.sqlite"
    shutil.copy(ingested_db_path, path)
    return path


@pytest.fixture
def replay_api() -> ReplayApi:
    return ReplayApi()
