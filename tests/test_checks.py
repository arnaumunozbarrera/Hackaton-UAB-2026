"""Basic checks on the debug alerts: raw-event rebuild, auto-close decisions, guards and auto tickets."""

import sqlite3

import pytest

from src.checks import ApiFacts, DbFacts, auto_ticket, load_context, load_ticket_schema, run_checks
from src.checks.db_events import log_record
from src.database.core import timestamp
from src.llm_triage.validator import validate_ticket
from tests.conftest import DEBUG_EVENTS, ReplayApi, read_jsonl

AUTO_CLOSED = {
    "ALR-20261005-000440": "false_positive",  # internet scanner blocked, never a 2xx
    "ALR-20261008-011833": "benign_true_positive",  # pentest IPs during CHG-2026-1042
    "ALR-20261009-001917": "benign_true_positive",  # Private Relay with a known device
    "ALR-20261011-011873": "benign_true_positive",  # trip notified to HR
    "ALR-20261007-011851": "benign_true_positive",  # NESSUS01 scan, CHG-2026-1049
    "ALR-20261016-011922": "benign_true_positive",  # Logisoft VPN, CHG-2026-1071
    "ALR-20261028-009418": "false_positive",  # sandbox clean and blocked
    "ALR-20261011-002565": "false_positive",  # benign TIP domain
}


@pytest.fixture
def conn(mini_db):
    connection = sqlite3.connect(mini_db)
    yield connection
    connection.close()


def check(conn, alert_id):
    return run_checks(conn, alert_id, facts=ApiFacts(ReplayApi(), DbFacts(conn)))


def test_stored_events_rebuild_to_their_raw_rows(conn):
    for item in read_jsonl(DEBUG_EVENTS):
        if item.get("context"):
            continue
        raw = dict(item["row"], timestamp=timestamp(item["row"]["timestamp"]))
        source, event = log_record(conn, raw["event_id"])
        assert source == item["source"]
        for key in raw.keys() | event.keys():
            assert raw.get(key) == event.get(key) or (raw.get(key) in ("", None, {}) and event.get(key) in ("", None))


def test_debug_alerts_close_or_stay_as_expected(conn):
    base = load_context(conn)
    facts = ApiFacts(ReplayApi(), DbFacts(conn))
    alert_ids = [r[0] for r in conn.execute("SELECT alert_id FROM alerts ORDER BY created_at")]
    assert len(alert_ids) == 20
    outcome = {aid: run_checks(conn, aid, base=base, facts=facts) for aid in alert_ids}
    assert {aid for aid, r in outcome.items() if r.discard} == set(AUTO_CLOSED)
    for aid, verdict in AUTO_CLOSED.items():
        assert outcome[aid].verdict == verdict
        assert not outcome[aid].guards and not outcome[aid].unexplained and outcome[aid].references


def test_known_device_needs_the_api_facts(conn):
    assert not run_checks(conn, "ALR-20261009-001917").discard  # DB alone: the earlier sign-ins are not stored
    assert check(conn, "ALR-20261009-001917").discard


@pytest.mark.parametrize(
    ("alert_id", "guard"),
    [
        ("ALR-20261023-011915", "Severidad high"),  # explained by CHG-2026-1078 but the rule is high
        ("ALR-20261009-002231", "OT ("),  # authorised OT access is still escalation-only
        ("ALR-20261005-000105", "G1:"),  # malicious TIP domain
        ("ALR-20261010-011795", "G2:"),  # Latrodectus alert on the same host the day before
    ],
)
def test_guards_keep_the_alert(conn, alert_id, guard):
    result = check(conn, alert_id)
    assert not result.discard
    assert any(g.startswith(guard) for g in result.guards)


def test_explained_event_with_free_text_is_kept(conn):
    result = check(conn, "ALR-20261005-000301")
    assert not result.discard and not result.guards
    assert result.open_text == ["EDR-0005329"]
    assert "CHG-2026-1031" in result.references


def test_chained_high_alert_blocks_until_explained(conn):
    aid = "ALR-20261005-000440"
    ip = conn.execute("SELECT value FROM alert_indicators WHERE alert_id = ?", (aid,)).fetchone()[0]
    created = conn.execute("SELECT created_at FROM alerts WHERE alert_id = ?", (aid,)).fetchone()[0]
    conn.execute(
        "INSERT INTO alerts (alert_id, created_at, rule_id, severity, status, description, evidence_json) "
        "VALUES ('ALR-TEST-1', ?, 'UC-EDR-001', 'high', 'new', 'test', '{}')",
        (created,),
    )
    conn.execute("INSERT INTO alert_indicators (alert_id, indicator_type, value) VALUES ('ALR-TEST-1', 'ip', ?)", (ip,))
    result = check(conn, aid)
    assert not result.discard and any("ALR-TEST-1" in g for g in result.guards)
    conn.execute("INSERT INTO alert_history (alert_id, verdict) VALUES ('ALR-TEST-1', 'false_positive')")
    assert check(conn, aid).discard


def test_auto_tickets_pass_the_validator(conn):
    schema = load_ticket_schema()
    for aid, verdict in AUTO_CLOSED.items():
        ticket = auto_ticket(conn, check(conn, aid))
        assert validate_ticket(ticket, schema, aid) == []
        assert ticket["verdict"] == verdict and ticket["recommended_actions"] == []
        assert not ticket["escalation"]["escalate"]


def test_kept_alert_has_no_auto_ticket(conn):
    with pytest.raises(ValueError):
        auto_ticket(conn, check(conn, "ALR-20261009-002231"))
