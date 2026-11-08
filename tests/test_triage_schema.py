"""Constraints of the triage result tables (model outputs and analyst decisions)."""

import sqlite3

import pytest

from src.database.schema import SCHEMA_PATH


@pytest.fixture
def db():
    connection = sqlite3.connect(":memory:")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    connection.execute("INSERT INTO detection_rules(rule_id) VALUES ('R1')")
    connection.execute("INSERT INTO alerts(alert_id,rule_id) VALUES ('A1','R1')")
    connection.commit()
    yield connection
    connection.close()


def run(db, stage="llm"):
    cursor = db.execute(
        "INSERT INTO triage_runs(alert_id,stage,status,started_at) VALUES ('A1',?,'running','2026-10-09T00:00:00Z')",
        (stage,),
    )
    return cursor.lastrowid


def test_runs_get_sequential_ids(db):
    assert [run(db), run(db, "auto_check")] == [1, 2]


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO triage_runs(alert_id,stage,status,started_at) VALUES ('A1','manual','running','t')",
        "INSERT INTO triage_runs(alert_id,stage,status,started_at) VALUES ('A1','llm','paused','t')",
        "INSERT INTO triage_tickets(run_id,alert_id,ticket_json,verdict,severity) VALUES (1,'A1','{}','maybe','low')",
        "INSERT INTO triage_tickets(run_id,alert_id,ticket_json,verdict,severity,ticket_confidence) "
        "VALUES (1,'A1','{}','true_positive','low',85)",
        "INSERT INTO triage_tickets(run_id,alert_id,ticket_json,verdict,severity) VALUES (1,'A1','no json','true_positive','low')",
        "INSERT INTO triage_checks(run_id,discard,verdict) VALUES (1,1,'true_positive')",
        "INSERT INTO analyst_decisions(alert_id,item,decision,analyst,decided_at) VALUES ('A1','verdict','maybe','x','t')",
        "INSERT INTO analyst_decisions(alert_id,item,decision,analyst,decided_at) VALUES ('A1','other','accepted','x','t')",
        "INSERT INTO analyst_decisions(alert_id,item,decision,analyst,decided_at) VALUES ('A1','action:1','accepted','x','t')",
        "INSERT INTO executed_actions(alert_id,action,target,status,executed_at) VALUES ('A1','x','y','maybe','t')",
    ],
)
def test_closed_domains_are_enforced(db, sql):
    run(db)
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(sql)


def test_ticket_and_decisions_reference_existing_rows(db):
    run_id = run(db)
    db.execute(
        "INSERT INTO triage_tickets(run_id,alert_id,ticket_json,verdict,severity,ticket_confidence) "
        "VALUES (?,'A1','{}','needs_more_info','medium',0.4)",
        (run_id,),
    )
    db.execute(
        "INSERT INTO analyst_decisions(alert_id,run_id,item,decision,override_verdict,analyst,decided_at) "
        "VALUES ('A1',?,'action:0','accepted',NULL,'ana','t')",
        (run_id,),
    )
    db.commit()
    db.execute(
        "INSERT INTO triage_tickets(run_id,alert_id,ticket_json,verdict,severity) VALUES (99,'A1','{}','true_positive','low')"
    )
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        db.commit()
