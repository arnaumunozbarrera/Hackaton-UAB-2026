"""Attack-chain reconstruction (N2): catalogue, report validation against the database, runner and service."""

from __future__ import annotations

import copy
import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from src.investigation import store
from src.investigation.catalogue import ALLOWED, InvestigationBackend, tool_definition
from src.investigation.report import REPORT_TOOL, report_schema, validate_report
from src.investigation.runner import ChainRunner, build_seed
from src.investigation.service import ChainService
from src.prompt_builder.tools import TOOL_NAME

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
pytestmark = pytest.mark.skipif(not (DOCS / "01_contexto/informe_incidente.schema.json").exists(), reason="no docs")

ESCALATED = {"title": "Robo de credenciales", "verdict": "true_positive", "severity": "high",
             "summary": "Login tras phishing", "escalation": {"escalate": True, "to": "N2", "reason": "TP high"}}  # fmt: skip


def make_db(path: Path) -> Path:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE detection_rules (rule_id TEXT PRIMARY KEY, name TEXT, tactic TEXT, technique_id TEXT);
        CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, created_at TEXT, rule_id TEXT, severity TEXT, status TEXT,
            description TEXT);
        CREATE TABLE dim_log (event_id TEXT PRIMARY KEY, source TEXT, timestamp TEXT, user_key TEXT, customer_id TEXT,
            hostname TEXT, src_ip TEXT, dst TEXT, action TEXT, result TEXT, sha256 TEXT, ref_id TEXT);
        CREATE TABLE bridge_alert_entity (alert_id TEXT, entity_type TEXT, entity_value TEXT, user_key TEXT,
            hostname TEXT, context_key TEXT);
        CREATE TABLE bridge_alert_event (alert_id TEXT, position INTEGER, event_id TEXT, state TEXT, reason TEXT,
            reference TEXT);
        CREATE TABLE alert_incidents (alert_id TEXT, incident_id TEXT, link_reason TEXT, link_score REAL,
            is_duplicate INTEGER, is_authorised INTEGER);
        CREATE VIEW bridge_alert_incident AS SELECT * FROM alert_incidents;
        CREATE TABLE triage_tickets (alert_id TEXT PRIMARY KEY, ticket_json TEXT, verdict TEXT, severity TEXT,
            escalate INTEGER, decision TEXT);
        INSERT INTO detection_rules VALUES ('UC-EML-001', 'Phishing', 'Initial Access', 'T1566'),
            ('UC-IDP-002', 'Login anómalo', 'Credential Access', 'T1078');
        INSERT INTO alerts VALUES ('ALR-1', '2026-10-03T09:00:00.000Z', 'UC-EML-001', 'medium', 'new', 'Correo'),
            ('ALR-2', '2026-10-05T10:00:00.000Z', 'UC-IDP-002', 'high', 'new', 'Login');
        INSERT INTO dim_log VALUES
            ('EML-1', 'email', '2026-10-03T08:59:00.000Z', 'ana', NULL, NULL, '203.0.113.9', 'evil.test', 'delivered', 'ok', NULL, 'm1'),
            ('IDP-1', 'idp_signins', '2026-10-05T09:58:00.000Z', 'ana', NULL, NULL, '203.0.113.9', NULL, 'signin', 'success', NULL, NULL),
            ('IDP-2', 'idp_signins', '2026-10-05T09:59:00.000Z', 'ana', NULL, NULL, '203.0.113.9', NULL, 'mfa', 'success', NULL, NULL);
        INSERT INTO bridge_alert_entity VALUES ('ALR-1', 'user', 'ana', 'ana', NULL, NULL),
            ('ALR-2', 'user', 'ana', 'ana', NULL, NULL), ('ALR-2', 'ip', '203.0.113.9', NULL, NULL, '203.0.113.9');
        INSERT INTO bridge_alert_event VALUES ('ALR-1', 0, 'EML-1', 'kept', '', ''), ('ALR-2', 0, 'IDP-1', 'kept', '', ''),
            ('ALR-2', 1, 'IDP-2', 'kept', '', '');
        INSERT INTO alert_incidents VALUES ('ALR-2', 'INC-DUP-x', 'duplicado', 1.0, 1, 0);
        """
    )
    conn.execute("INSERT INTO triage_tickets VALUES ('ALR-2', ?, 'true_positive', 'high', 1, NULL)",
                 (json.dumps(ESCALATED),))  # fmt: skip
    conn.commit()
    conn.close()
    return path


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return make_db(tmp_path / "mini.sqlite")


def good_report() -> dict:
    return {
        "incident_id": "INC-N2-1", "title": "Phishing con robo de credenciales", "alert_ids": ["ALR-2", "ALR-1"],
        "related_incidents": ["INC-DUP-x"], "patient_zero": "ana", "initial_access": "Correo de phishing (T1566)",
        "attack_summary": "Ana recibió un correo de phishing el día 3 y dos días después se inició sesión con su cuenta "
                          "desde la misma IP del remitente.",
        "window": {"start": "2026-10-03T08:59:00.000Z", "end": "2026-10-05T09:59:00.000Z"},
        "timeline": [
            {"timestamp": "2026-10-03T08:59:00.000Z", "event_id": "EML-1", "alert_id": "ALR-1",
             "description": "Correo entregado", "phase": "Initial Access"},
            {"timestamp": "2026-10-05T09:58:00.000Z", "event_id": "IDP-1", "alert_id": "ALR-2",
             "description": "Inicio de sesión", "phase": "Credential Access"},
        ],
        "related_alerts": [{"alert_id": "ALR-1", "relation": "correo de origen"}],
        "scope": {"users": ["ana"], "hosts": [], "data": "ninguno", "business_impact": "bajo"},
        "root_cause": "Credenciales robadas por phishing", "containment_plan": [], "confidence": 0.8,
    }  # fmt: skip


class ScriptedLLM:
    model = "scripted"

    def __init__(self, replies: list[dict]) -> None:
        self.replies, self.calls = replies, 0

    def create(self, **kwargs):
        reply = self.replies[min(self.calls, len(self.replies) - 1)]
        self.calls += 1
        return {"content": [reply], "stop_reason": "tool_use", "usage": {"input_tokens": 1, "output_tokens": 1}}


def test_catalogue_is_read_only_and_bounded(db: Path) -> None:
    backend = InvestigationBackend(db)
    names = tool_definition()["input_schema"]["properties"]["consultas"]["items"]["properties"]["consulta"]["enum"]
    assert set(names) == set(ALLOWED) and "runbook_text" not in names and "user_daily" in names
    with pytest.raises(ValueError):
        backend.execute("drop_everything", [])
    rows = backend.execute("user_daily", ["TARVIA\\Ana", "2026-10-01", "2026-10-06"])  # identity normalised
    assert [r["day"] for r in rows] == ["2026-10-03", "2026-10-05", "2026-10-05"]
    assert [r["alert_id"] for r in backend.execute("entity_alerts", ["ana", "2026-10-01", "2026-10-06"])] == [
        "ALR-1", "ALR-2"]  # fmt: skip
    with pytest.raises(sqlite3.OperationalError):
        backend._conn().execute("DELETE FROM alerts")


def test_seed_requires_triage_description(db: Path) -> None:
    backend = InvestigationBackend(db)
    seed = build_seed(backend, "ALR-2")
    assert seed.triage["ticket"]["summary"] == "Login tras phishing"
    assert "ALR-1" in json.dumps(seed.entity_alerts) and seed.incidents[0]["incident_id"] == "INC-DUP-x"
    assert "Descripción del triaje N1" in seed.message()
    with pytest.raises(LookupError):
        build_seed(backend, "ALR-1")


def test_validation_is_grounded_in_the_database(db: Path) -> None:
    schema, backend = report_schema(DOCS), InvestigationBackend(db)
    assert validate_report(good_report(), schema, "ALR-2", backend) == []
    bad = copy.deepcopy(good_report())
    bad["timeline"][0]["event_id"] = "EML-999"
    bad["related_incidents"] = ["INC-INVENTADO"]
    bad["timeline"].reverse()
    errors = " | ".join(validate_report(bad, schema, "ALR-2", backend))
    assert "EML-999" in errors and "INC-INVENTADO" in errors and "cronológico" in errors
    assert any("ALR-9" in e for e in validate_report(good_report(), schema, "ALR-9", backend))
    missing = {k: v for k, v in good_report().items() if k != "attack_summary"}
    assert any("attack_summary" in e for e in validate_report(missing, schema, "ALR-2", backend))


def test_runner_repairs_an_invented_id(db: Path) -> None:
    bad = copy.deepcopy(good_report())
    bad["timeline"][0]["event_id"] = "EML-404"
    replies = [
        {"type": "tool_use", "id": "c1", "name": TOOL_NAME, "input": {"motivo": "Busco el origen del acceso de ana",
         "consultas": [{"consulta": "user_daily", "parametros": ["ana", "2026-09-28", "2026-10-06"]}]}},
        {"type": "tool_use", "id": "r1", "name": REPORT_TOOL, "input": bad},
        {"type": "tool_use", "id": "r2", "name": REPORT_TOOL, "input": good_report()},
    ]  # fmt: skip
    result = ChainRunner(InvestigationBackend(db), DOCS).run("ALR-2", ScriptedLLM(replies))
    assert result.valid and result.attempts == 2 and result.report["patient_zero"] == "ana"
    kinds = [s["type"] for s in result.transcript]
    assert kinds[:2] == ["semilla", "contexto"] and kinds.count("informe") == 2


def test_mock_run_and_store_roundtrip(db: Path) -> None:
    result = ChainRunner(InvestigationBackend(db), DOCS).run("ALR-2", mode="mock").to_dict()
    assert result["valid"], result["errors"]
    assert [s["event_id"] for s in result["report"]["timeline"]] == ["IDP-1", "IDP-2"]
    conn = sqlite3.connect(db)
    store.ensure(conn)
    store.save(conn, result, "test")
    got = store.get(conn, "ALR-2")
    assert got["valid"] and got["trigger"] == "test" and got["report"]["incident_id"].startswith("INC-MOCK")


def test_service_triggers_only_escalated_and_once(db: Path) -> None:
    conn = sqlite3.connect(db, check_same_thread=False)
    svc = ChainService(db, conn, threading.RLock(), DOCS, mode="mock")
    assert svc.maybe_start("ALR-2", {"escalation": {"escalate": False}}, "triage") is None
    job = svc.maybe_start("ALR-2", ESCALATED, "triage")
    assert job and svc.start("ALR-2") == job  # a queued/running job is reused
    for _ in range(100):
        if svc.job(job)["status"] not in ("queued", "running"):
            break
        time.sleep(0.05)
    assert svc.job(job)["status"] == "done"
    out = svc.get("ALR-2")
    assert out["chain"]["valid"] and out["chain"]["trigger"] == "triage"
    assert svc.maybe_start("ALR-2", ESCALATED, "triage") is None  # stored report kept
