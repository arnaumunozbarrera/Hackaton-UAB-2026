"""End-to-end workflow on the debug feed: ingest -> checks -> mock LLM -> stored results (no network)."""

import json
import shutil
import sqlite3

import pytest

from src import main as cli
from src.workflow import Triage
from tests.conftest import ReplayApi

AUTO_CLOSED = 8


@pytest.fixture
def empty_db(context_db_path, tmp_path):
    path = tmp_path / "workflow.sqlite"
    shutil.copy(context_db_path, path)
    return path


def scalar(path, sql, params=()):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(sql, params).fetchone()[0]
    finally:
        conn.close()


def test_full_feed_with_mock_llm(empty_db, capsys):
    assert cli.main(["--llm", "mock", "--db", str(empty_db)], api=ReplayApi()) == 0
    out = capsys.readouterr().out
    assert out.count("auto_closed") == AUTO_CLOSED and out.count("llm_done") == 20 - AUTO_CLOSED
    assert scalar(empty_db, "SELECT COUNT(*) FROM alerts") == 20
    assert scalar(empty_db, "SELECT COUNT(*) FROM triage_runs WHERE stage = 'auto_check' AND status = 'done'") == 20
    assert scalar(empty_db, "SELECT COUNT(*) FROM triage_checks WHERE discard = 1") == AUTO_CLOSED
    assert (
        scalar(empty_db, "SELECT COUNT(*) FROM triage_runs WHERE stage = 'llm' AND status = 'done' AND valid = 1") == 12
    )
    assert scalar(empty_db, "SELECT COUNT(*) FROM triage_tickets WHERE valid = 1") == 20
    rows = json.loads(scalar(empty_db, "SELECT rows_json FROM triage_context_requests LIMIT 1"))
    assert rows[0]["consulta"] == "runbook_text" and rows[0]["filas"] == 1
    transcript = json.loads(scalar(empty_db, "SELECT transcript_json FROM triage_runs WHERE stage = 'llm' LIMIT 1"))
    assert transcript and all("resultados" not in e for e in transcript)
    assert scalar(empty_db, "SELECT COUNT(*) FROM alert_history") == 0  # only the analyst writes alert_history


def test_limit_and_checks_only(empty_db, capsys):
    assert cli.main(["--limit", "3", "--db", str(empty_db)], api=ReplayApi()) == 0
    assert scalar(empty_db, "SELECT COUNT(*) FROM alerts") == 3
    assert scalar(empty_db, "SELECT COUNT(*) FROM triage_runs WHERE stage = 'llm'") == 0
    assert "pending_llm" in capsys.readouterr().out


def test_one_failing_alert_does_not_stop_the_queue(empty_db, monkeypatch, capsys):
    original = Triage.triage_llm

    def flaky(self, alert_id, analyst_note=""):
        if alert_id == "ALR-20261009-011791":
            raise RuntimeError("LLM caído")
        return original(self, alert_id, analyst_note)

    monkeypatch.setattr(Triage, "triage_llm", flaky)
    cli.main(["--llm", "mock", "--db", str(empty_db)], api=ReplayApi())
    assert "ALR-20261009-011791: llm_error" in capsys.readouterr().out
    assert scalar(empty_db, "SELECT COUNT(*) FROM alerts") == 20
    assert scalar(empty_db, "SELECT COUNT(*) FROM triage_runs WHERE stage = 'llm' AND valid = 1") == 11


def test_llm_error_is_stored_on_the_run(empty_db, monkeypatch):
    cli.main(["--limit", "1", "--db", str(empty_db)], api=ReplayApi())
    alert_id = scalar(empty_db, "SELECT alert_id FROM alerts")
    with Triage(empty_db, llm_mode="mock") as triage:
        monkeypatch.setattr(triage.runner, "run", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        outcome = triage.process(alert_id)
    assert outcome.status == "llm_error"
    assert "boom" in scalar(empty_db, "SELECT errors_json FROM triage_runs WHERE stage = 'llm' AND status = 'error'")


def test_check_failure_is_isolated(empty_db, monkeypatch, capsys):
    from src.workflow import pipeline

    real = pipeline.run_checks

    def broken(conn, alert_id, **kw):
        if alert_id == "ALR-20261005-000105":
            raise ValueError("dato corrupto")
        return real(conn, alert_id, **kw)

    monkeypatch.setattr(pipeline, "run_checks", broken)
    assert cli.main(["--db", str(empty_db)], api=ReplayApi()) == 1
    assert "ALR-20261005-000105: error" in capsys.readouterr().err
    assert scalar(empty_db, "SELECT COUNT(*) FROM triage_runs WHERE status = 'error'") == 1
    assert scalar(empty_db, "SELECT COUNT(*) FROM triage_runs WHERE status = 'done'") == 19


def test_rerun_of_a_stored_alert_adds_runs(empty_db):
    cli.main(["--limit", "1", "--db", str(empty_db)], api=ReplayApi())
    alert_id = scalar(empty_db, "SELECT alert_id FROM alerts")
    assert cli.main(["--alert", alert_id, "--llm", "mock", "--db", str(empty_db)], api=ReplayApi()) == 0
    assert scalar(empty_db, "SELECT COUNT(*) FROM triage_runs WHERE alert_id = ?", (alert_id,)) >= 2
