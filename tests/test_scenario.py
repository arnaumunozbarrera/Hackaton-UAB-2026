"""Demo scenario: checkpoints, backlog closing, arrival of a new batch and rollback."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from src.database import scenario
from src.triage_flow import store

ROOT = Path(__file__).resolve().parents[1]
PIPELINE_SQL = ROOT / "src" / "database" / "pipeline.sql"


def make_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE detection_rules (rule_id TEXT PRIMARY KEY, name TEXT, source_product TEXT, tactic TEXT,
            runbook_id TEXT);
        CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, created_at TEXT, rule_id TEXT, severity TEXT);
        CREATE TABLE alert_events (alert_id TEXT, position INTEGER, event_id TEXT);
        CREATE TABLE alert_users (alert_id TEXT, user_id TEXT);
        INSERT INTO detection_rules VALUES ('R1', 'Regla', 'NGFW', 'Discovery', 'RB-01');
        INSERT INTO alerts VALUES ('OLD1', '2026-10-05T07:00:00Z', 'R1', 'medium'),
                                  ('OLD2', '2026-10-05T07:10:00Z', 'R1', 'low'),
                                  ('NEW1', '2026-10-05T07:20:00Z', 'R1', 'medium');
        INSERT INTO alert_events VALUES ('OLD1', 0, 'E1'), ('NEW1', 0, 'E9');
        INSERT INTO alert_users VALUES ('NEW1', 'U1');
        """
    )
    conn.executescript(PIPELINE_SQL.read_text(encoding="utf-8"))
    for aid in ("OLD1", "NEW1"):
        store.save_ticket(conn, aid, {"verdict": "needs_more_info", "severity": "medium"}, valid=True, route="llm")
    conn.commit()
    conn.close()


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(scenario, "CHECKPOINTS", tmp_path / "checkpoints")
    db = tmp_path / "live.sqlite"
    make_db(db)
    alerts = tmp_path / "batch.jsonl"
    alerts.write_text(json.dumps({"alert_id": "NEW1"}) + "\n" + json.dumps({"alert_id": "NEW2"}) + "\n")
    return db, alerts


def test_prepare_closes_backlog_removes_incoming_and_checkpoints(env):
    db, alerts = env
    out = scenario.prepare(db, alerts)
    assert out["already_stored_removed"] == ["NEW1"] and out["backlog_closed"] == 2
    assert out["checkpoints"] == ["before-batch", "baseline-batch"]
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM alert_users").fetchone()[0] == 0  # NEW1 rows gone
    assert conn.execute("SELECT COUNT(*) FROM triage_tickets WHERE alert_id = 'OLD1'").fetchone()[0] == 1  # kept
    assert store.queue(conn) == []  # the backlog no longer appears as pending
    assert conn.execute("SELECT value FROM pipeline_meta WHERE key = 'filter_scope'").fetchone()[0] == "database"
    # a new alert arrives: it is the only pending one
    conn.execute("INSERT INTO alerts VALUES ('NEW2', '2026-10-09T09:00:00Z', 'R1', 'high')")
    store.save_ticket(conn, "NEW2", {"verdict": "needs_more_info", "severity": "high"}, valid=True, route="llm")
    assert [r["alert_id"] for r in store.queue(conn)] == ["NEW2"]
    conn.close()
    names = [m["name"] for m in scenario.list_checkpoints()]
    assert names == ["baseline-batch", "before-batch"]


def test_restore_returns_to_the_baseline_and_to_the_original(env):
    db, alerts = env
    scenario.prepare(db, alerts)
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO alerts VALUES ('NEW2', '2026-10-09T09:00:00Z', 'R1', 'high')")
    conn.commit()
    conn.close()
    assert scenario.restore(db, "baseline-batch")["alerts"] == 2  # OLD1, OLD2; the batch not received yet
    original = scenario.restore(db, "before-batch")
    assert original["alerts"] == 3 and original["backlog_closed"] == 0 and original["pending_tickets"] == 2
    with pytest.raises(FileExistsError):
        scenario.checkpoint(db, "before-batch")


def test_prepare_removes_incoming_severity_evidence_and_preserves_other_history(tmp_path, monkeypatch):
    monkeypatch.setattr(scenario, "CHECKPOINTS", tmp_path / "checkpoints")
    db = tmp_path / "severity.sqlite"
    with sqlite3.connect(db) as conn:
        conn.executescript((ROOT / "src/database/schema.sql").read_text(encoding="utf-8"))
        conn.executescript(PIPELINE_SQL.read_text(encoding="utf-8"))
        conn.execute("INSERT INTO detection_rules(rule_id) VALUES ('R1')")
        for aid in ("OLD1", "NEW1"):
            conn.execute("INSERT INTO alerts(alert_id,rule_id,severity) VALUES (?,'R1','medium')", (aid,))
            for revision in (1, 2):
                cursor = conn.execute(
                    "INSERT INTO severity_assessments (alert_id,rule_severity,criticality,base_severity,adjustment,"
                    "final_severity,verdict,method,rationale,rules_version,policy_hash,input_snapshot_json,assessed_at) "
                    "VALUES (?,'medium','Media','medium',0,'medium','needs_more_info','matrix','Matrix calculation',"
                    "'matrix-v1',?,?, '2026-11-08T00:00:00Z')",
                    (aid, "0" * 64, json.dumps({"revision": revision})),
                )
                conn.executemany(
                    "INSERT INTO severity_evidence (assessment_id,condition,status,source,reference,finding,details_json) "
                    "VALUES (?,'matrix_lookup','confirmed','matrix','policy',?,'{}')",
                    [(cursor.lastrowid, f"{aid}: revision {revision}, fact {fact}") for fact in range(3)],
                )
        original_assessments = conn.execute("SELECT * FROM severity_assessments ORDER BY assessment_id").fetchall()
        original_evidence = conn.execute("SELECT * FROM severity_evidence ORDER BY evidence_id").fetchall()
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []

    alerts = tmp_path / "batch.jsonl"
    alerts.write_text(json.dumps({"alert_id": "NEW1"}) + "\n", encoding="utf-8")
    result = scenario.prepare(db, alerts)

    assert result["rows_removed"]["severity_assessments"] == 2
    assert result["rows_removed"]["severity_evidence"] == 6
    kept = [row for row in original_assessments if row[1] == "OLD1"]
    kept_ids = {row[0] for row in kept}
    kept_evidence = [row for row in original_evidence if row[1] in kept_ids]
    for path in (db, scenario.CHECKPOINTS / "baseline-batch.sqlite"):
        with sqlite3.connect(path) as conn:
            assert conn.execute("SELECT * FROM severity_assessments ORDER BY assessment_id").fetchall() == kept
            assert conn.execute("SELECT * FROM severity_evidence ORDER BY evidence_id").fetchall() == kept_evidence
            assert conn.execute("PRAGMA foreign_key_check").fetchall() == []

    scenario.restore(db, "before-batch")
    with sqlite3.connect(db) as conn:
        assert (
            conn.execute("SELECT * FROM severity_assessments ORDER BY assessment_id").fetchall() == original_assessments
        )
        assert conn.execute("SELECT * FROM severity_evidence ORDER BY evidence_id").fetchall() == original_evidence
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_demo_api_serves_only_the_batch(monkeypatch):
    pytest.importorskip("fastapi")
    if not (ROOT / "docs" / "06_herramientas" / "mock_soc_api.py").exists():
        pytest.skip("docs/ not available")
    monkeypatch.setenv("TARVIA_ALERTS_FILE", "data/demo_alertas_comunes.jsonl")
    if not (ROOT / "data" / "demo_alertas_comunes.jsonl").exists():
        pytest.skip("demo file not available")
    from fastapi.testclient import TestClient

    from src import demo_api

    body = TestClient(demo_api.app).get("/alerts", params={"limit": 100}).json()
    assert body["total"] == 10 and all(a["status"] == "new" for a in body["items"])
    assert demo_api.mock.LOGFILE.endswith(str(Path("data") / "containment_log.jsonl"))
