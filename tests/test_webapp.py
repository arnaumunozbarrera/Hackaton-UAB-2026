"""Web UI API: queue status, detail, analyst decisions, alert_history, approvals/containment and OT refusal."""

import json
import shutil
import sqlite3

import pytest
from fastapi.testclient import TestClient

from src import main as cli
from src.webapp import create_app
from src.webapp.actions import api_action
from src.workflow.store import now
from tests.conftest import ReplayApi

LATRODECTUS = "ALR-20261009-011791"
SCANNER = "ALR-20261005-000440"


@pytest.fixture(scope="module")
def triaged_db(context_db_path, tmp_path_factory):
    path = tmp_path_factory.mktemp("web") / "web.sqlite"
    shutil.copy(context_db_path, path)
    cli.main(["--llm", "mock", "--db", str(path)], api=ReplayApi())
    return path


@pytest.fixture
def env(triaged_db, tmp_path):
    path = tmp_path / "web.sqlite"
    shutil.copy(triaged_db, path)
    api = ReplayApi()
    return TestClient(create_app(path, api=api)), api, path


def add_ticket(path, alert_id, actions, verdict="true_positive"):
    """A stored LLM ticket with the given recommended actions; returns its run_id."""
    conn = sqlite3.connect(path)
    run_id = conn.execute(
        "INSERT INTO triage_runs (alert_id, stage, model, status, started_at, finished_at, valid) "
        "VALUES (?, 'llm', 'test', 'done', ?, ?, 1)",
        (alert_id, now(), now()),
    ).lastrowid
    ticket = {"ticket_id": "TKT-T", "alert_ids": [alert_id], "title": "t", "verdict": verdict, "confidence": 0.8,
              "severity": "high", "summary": "s", "evidence": [], "recommended_actions": actions,
              "escalation": {"escalate": True}}  # fmt: skip
    conn.execute(
        "INSERT INTO triage_tickets (run_id, alert_id, ticket_id, ticket_json, verdict, severity, ticket_confidence, "
        "valid, created_at) VALUES (?, ?, 'TKT-T', ?, ?, 'high', 0.8, 1, ?)",
        (run_id, alert_id, json.dumps(ticket), verdict, now()),
    )
    conn.commit()
    conn.close()
    return run_id


def count(path, sql, params=()):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(sql, params).fetchone()[0]
    finally:
        conn.close()


def decide(client, alert_id, **body):
    return client.post(f"/api/alerts/{alert_id}/decisions", json={"analyst": "Ana N1"} | body)


def test_queue_statuses_and_detail(env):
    client, _, _ = env
    queue = client.get("/api/alerts").json()
    statuses = [a["status"] for a in queue]
    assert statuses.count("auto_closed") == 8 and statuses.count("awaiting_analyst") == 12
    detail = client.get(f"/api/alerts/{LATRODECTUS}").json()
    assert detail["status"] == "awaiting_analyst" and len(detail["events"]) == 5
    assert detail["events"][0]["event"]["hostname"] == "WS-BCN-1770"
    assert detail["checks"]["guards"] and detail["llm"]["transcript"] and detail["context_requests"]
    assert detail["ticket"]["origin"] == "llm" and detail["alert_history"] is None
    assert client.get("/api/alerts/ALR-NOPE").status_code == 404


def test_accepting_the_verdict_writes_alert_history(env):
    client, _, path = env
    r = decide(client, SCANNER, item="verdict", decision="accepted")
    assert r.status_code == 200 and r.json()["alert_history"] == "false_positive"
    assert client.get(f"/api/alerts/{SCANNER}").json()["status"] == "accepted"
    assert count(path, "SELECT verdict FROM alert_history WHERE alert_id = ?", (SCANNER,)) == "false_positive"


def test_rejecting_does_not_write_alert_history(env):
    client, _, path = env
    assert decide(client, SCANNER, item="verdict", decision="rejected", comment="no me convence").status_code == 200
    assert count(path, "SELECT COUNT(*) FROM alert_history") == 0
    assert client.get(f"/api/alerts/{SCANNER}").json()["status"] == "rejected"


def test_needs_more_info_requires_a_final_verdict(env):
    client, _, path = env
    assert decide(client, LATRODECTUS, item="verdict", decision="accepted").status_code == 400
    r = decide(client, LATRODECTUS, item="verdict", decision="accepted", override_verdict="true_positive")
    assert r.status_code == 200
    assert count(path, "SELECT verdict FROM alert_history WHERE alert_id = ?", (LATRODECTUS,)) == "true_positive"
    assert client.get("/api/decisions").json()[0]["override_verdict"] == "true_positive"


def test_disruptive_action_runs_with_approval_once(env):
    client, api, path = env
    run_id = add_ticket(path, LATRODECTUS, [{"action": "Aislar el equipo", "target": "WS-BCN-1770",
                                             "requires_approval": True}])  # fmt: skip
    r = decide(client, LATRODECTUS, item="action:0", decision="accepted", run_id=run_id).json()
    assert r["execution"]["status"] == "ok" and r["execution"]["action"] == "isolate_host"
    assert api.containment[0]["approval_token"] in api.approvals
    assert api.approvals[api.containment[0]["approval_token"]]["approver"] == "Ana N1"
    again = decide(client, LATRODECTUS, item="action:0", decision="accepted", run_id=run_id)
    assert again.status_code == 409 and len(api.containment) == 1
    assert count(path, "SELECT status FROM executed_actions WHERE run_id = ?", (run_id,)) == "ok"


def test_block_ioc_needs_no_approval_and_rejected_actions_do_nothing(env):
    client, api, path = env
    run_id = add_ticket(path, LATRODECTUS, [
        {"action": "Bloquear IOC", "target": "aplihartom.com", "requires_approval": False},
        {"action": "Deshabilitar usuario", "target": "marta.puig", "requires_approval": True},
    ])  # fmt: skip
    r = decide(client, LATRODECTUS, item="action:0", decision="accepted", run_id=run_id).json()
    assert r["execution"]["action"] == "block_ioc" and not api.approvals
    decide(client, LATRODECTUS, item="action:1", decision="rejected", run_id=run_id)
    assert len(api.containment) == 1
    assert count(path, "SELECT COUNT(*) FROM analyst_decisions WHERE run_id = ?", (run_id,)) == 2


def test_ot_targets_are_refused_and_escalations_are_only_recorded(env):
    client, api, path = env
    ot_host = count(path, "SELECT hostname FROM assets WHERE zone_id = 'LOGISTICS-OT' LIMIT 1")
    run_id = add_ticket(path, "ALR-20261009-002231", [
        {"action": "Aislar equipo", "target": ot_host, "requires_approval": True},
        {"action": "Escalar a Operaciones", "target": "N2 y Operaciones", "requires_approval": False},
    ])  # fmt: skip
    r = decide(client, "ALR-20261009-002231", item="action:0", decision="accepted", run_id=run_id).json()
    assert r["execution"]["status"] == "refused" and "OT" in r["execution"]["result"]["detail"]
    assert not api.containment and not api.approvals
    r = decide(client, "ALR-20261009-002231", item="action:1", decision="accepted", run_id=run_id).json()
    assert r["execution"]["executed"] is False
    assert count(path, "SELECT COUNT(*) FROM executed_actions WHERE run_id = ?", (run_id,)) == 1


def test_bad_requests(env):
    client, _, _ = env
    assert decide(client, SCANNER, item="drop table", decision="accepted").status_code == 422
    assert decide(client, SCANNER, item="action:3", decision="accepted").status_code == 400
    assert decide(client, SCANNER, item="verdict", decision="accepted", analyst="").status_code == 422
    assert decide(client, SCANNER, item="verdict", decision="accepted", override_verdict="x").status_code == 400


def test_stats_and_frontend(env):
    client, _, _ = env
    decide(client, SCANNER, item="verdict", decision="accepted")
    stats = client.get("/api/stats").json()
    assert stats["alerts"] == 20 and stats["auto_closed"] == 8 and stats["decisions"]["agreed"] == 1
    assert stats["llm"]["runs"] == 12
    assert client.get("/ui/").status_code == 200


@pytest.mark.parametrize(
    ("text", "expected"),
    [("Aislar el equipo", "isolate_host"), ("Restablecer la contraseña", "reset_password"),
     ("Revocar sesiones", "revoke_sessions"), ("Deshabilitar la cuenta", "disable_user"),
     ("Purgar el correo", "purge_email"), ("Bloquear dominio", "block_ioc"), ("Desactivar access key", "disable_access_key"),
     ("Escalar a N2", None), ("Revisar con el usuario", None)],
)  # fmt: skip
def test_action_mapping(text, expected):
    assert api_action({"action": text}) == expected
