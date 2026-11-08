"""Exercise data-loss boundaries, SQLite constraints and the ingested originals."""

import json
import sqlite3
from collections import defaultdict

import pytest

from src.database import build
from src.database.alerts import indicator_values
from src.database.core import Directory, Writer, timestamp
from src.database.logs import SPECS, transform
from src.database.schema import ROOT, SCHEMA_PATH, generate_schema


@pytest.fixture
def memory_db():
    connection = sqlite3.connect(":memory:")
    connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    yield connection
    connection.close()


@pytest.fixture
def directory():
    return Directory(
        [{"user_id": "U1", "username": "alice", "upn": "alice@tarvia.example", "display_name": "Alice"}],
        [{"asset_id": "A1", "hostname": "WS-1", "ip": "10.0.0.1"}],
    )


@pytest.mark.parametrize("observed", ["alice", "ALICE", "alice@tarvia.example", "TARVIA\\alice"])
def test_directory_resolves_only_supported_names(directory, observed):
    assert directory.user(observed) == "U1"


@pytest.mark.parametrize("observed", ["OTHER\\alice", "alice@other.example", "NT AUTHORITY\\SYSTEM"])
def test_external_identifiers_do_not_become_internal_users(directory, observed):
    assert directory.user(observed) is None


@pytest.mark.parametrize(
    "local,utc", [("2026-10-13 10:00", "2026-10-13T08:00:00.000Z"), ("2026-10-27 10:00", "2026-10-27T09:00:00.000Z")]
)
def test_madrid_change_windows_respect_dst(local, utc):
    assert timestamp(local, local=True) == utc


def test_naive_log_timestamps_are_rejected():
    with pytest.raises(ValueError, match="timezone"):
        timestamp("2026-10-13 10:00")


def test_false_zero_and_empty_json_are_not_lost(memory_db):
    writer = Writer(memory_db)
    writer.add("users", {"user_id": "U1", "username": "alice", "upn": "alice@tarvia.example", "privileged": False})
    writer.add("logs", {"event_id": "E1", "timestamp": "2026-10-13T08:00:00.000Z", "source": "vpn"})
    writer.add("vpn_logs", {"event_id": "E1", "user_id": "U1", "bytes": 0, "mfa_result": ""})
    writer.add("detection_rules", {"rule_id": "R1"})
    evidence = {"allowed": False, "bytes": 0, "nested": {}, "subject": "texto '); DROP TABLE users; --"}
    writer.add("alerts", {"alert_id": "A1", "rule_id": "R1", "evidence_json": evidence})
    writer.flush_all()
    memory_db.commit()
    assert memory_db.execute("SELECT privileged FROM users").fetchone() == (0,)
    assert memory_db.execute("SELECT bytes,mfa_result FROM vpn_logs").fetchone() == (0, None)
    assert json.loads(memory_db.execute("SELECT evidence_json FROM alerts").fetchone()[0]) == evidence


def test_uninventoried_observations_survive(directory):
    source = {
        "event_id": "E1",
        "timestamp": "2026-10-13T08:00:00.000Z",
        "hostname": "WS-1",
        "user": "NT AUTHORITY\\SYSTEM",
    }
    result = transform(source, "edr_events", directory)
    assert result["user_id"] is None
    assert result["unresolved_user"] == source["user"]
    assert result["asset_id"] == "A1"


def test_unknown_fields_fail_instead_of_disappearing(directory):
    with pytest.raises(ValueError, match="Unmapped"):
        transform({"unexpected": "must not vanish"}, "vpn", directory)


def test_source_guard_rejects_wrong_detail_table(memory_db):
    memory_db.execute("INSERT INTO logs VALUES ('E1','2026-10-13T08:00:00.000Z','vpn')")
    with pytest.raises(sqlite3.IntegrityError, match="Wrong source"):
        memory_db.execute("INSERT INTO edr_logs(event_id) VALUES ('E1')")


@pytest.mark.parametrize("verdict", ["true_positive", "false_positive", "benign_true_positive"])
def test_history_accepts_one_result_per_existing_alert(memory_db, verdict):
    memory_db.execute("INSERT INTO detection_rules(rule_id) VALUES ('R1')")
    memory_db.execute("INSERT INTO alerts(alert_id,rule_id) VALUES ('A1','R1')")
    memory_db.execute("INSERT INTO alert_history VALUES ('A1',?)", (verdict,))
    memory_db.commit()
    with pytest.raises(sqlite3.IntegrityError):
        memory_db.execute("INSERT INTO alert_history VALUES ('A1',?)", (verdict,))
    with pytest.raises(sqlite3.IntegrityError):
        memory_db.execute("UPDATE alert_history SET verdict='needs_more_info'")


def test_history_cannot_reference_missing_alert(memory_db):
    memory_db.execute("INSERT INTO alert_history VALUES ('missing','true_positive')")
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        memory_db.commit()


def test_json_constraints_reject_malformed_evidence(memory_db):
    memory_db.execute("INSERT INTO detection_rules(rule_id) VALUES ('R1')")
    with pytest.raises(sqlite3.IntegrityError):
        memory_db.execute("INSERT INTO alerts(alert_id,rule_id,evidence_json) VALUES ('A1','R1','not json')")


def test_ranges_expand_without_inventing_an_indicator():
    assert indicator_values("ip", "10.40.16.21-26") == [f"10.40.16.{number}" for number in range(21, 27)]
    for value in ["10.40.16.26-21", "10.40.16.1-999999999"]:
        with pytest.raises(ValueError):
            indicator_values("ip", value)


def test_failed_rebuild_does_not_replace_existing_file(tmp_path, monkeypatch):
    output = tmp_path / "kept.sqlite"
    output.write_bytes(b"existing database must survive")
    before = output.read_bytes()
    data = tmp_path / "sources"
    data.mkdir()

    def fail(*args):
        raise ValueError("simulated ingestion failure")

    monkeypatch.setattr(build, "load_inventory", fail)
    with pytest.raises(ValueError, match="simulated"):
        build.build_database(output, data=data, replace=True, progress=lambda message: None)
    assert output.read_bytes() == before
    assert not list(tmp_path.glob(".*.building-*.sqlite"))


def test_context_only_build_has_inventory_but_no_alerts_or_logs(tmp_path):
    output = tmp_path / "context.sqlite"
    result = build.build_database(output, context_only=True, progress=lambda message: None)
    assert result["mode"] == "context_only"
    connection = sqlite3.connect(output)
    try:
        for table in ["alerts", "alert_events", "logs", "email_logs", "alert_history"]:
            assert connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] == 0  # noqa: S608
        for table in ["users", "assets", "changes", "threat_intelligence", "detection_rules", "runbooks"]:
            assert connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] > 0  # noqa: S608
    finally:
        connection.close()


def test_versioned_schema_matches_generator():
    assert SCHEMA_PATH.read_text(encoding="utf-8") == generate_schema()


@pytest.fixture(scope="module")
def loaded_db():
    path = ROOT / "data" / "tarvia.sqlite"
    if not path.exists():
        pytest.skip("Run python -m src.database.build to exercise the ingested dataset")
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    if connection.execute("SELECT COUNT(*) FROM logs").fetchone()[0] == 0:
        connection.close()
        pytest.skip("data/tarvia.sqlite is a context-only build; these checks need a full build")
    yield connection
    connection.close()


@pytest.mark.integration
def test_every_log_source_has_all_its_original_rows(loaded_db):
    actual = dict(loaded_db.execute("SELECT source,COUNT(*) FROM logs GROUP BY source"))
    for source, spec in SPECS.items():
        extension = ".csv" if source in {"dns", "firewall", "proxy"} else ".jsonl"
        with (ROOT / "docs/04_logs" / (source + extension)).open("rb") as stream:
            count = sum(bool(line.strip()) for line in stream) - (extension == ".csv")
        assert actual[source] == count
        assert loaded_db.execute(f'SELECT COUNT(*) FROM "{spec.table}"').fetchone()[0] == count  # noqa: S608
    assert sum(actual.values()) == 814471


@pytest.mark.integration
def test_every_alert_keeps_evidence_metadata_and_ordered_events(loaded_db):
    records = {
        r[0]: r[1:]
        for r in loaded_db.execute(
            "SELECT a.alert_id,a.evidence_json,r.name,r.source_product,r.tactic,r.technique_id,r.technique_name,r.runbook_id "
            "FROM alerts a JOIN detection_rules r USING(rule_id)"
        )
    }
    events = defaultdict(list)
    for alert, event in loaded_db.execute("SELECT alert_id,event_id FROM alert_events ORDER BY alert_id,position"):
        events[alert].append(event)
    with (ROOT / "docs/03_alertas/alertas.jsonl").open(encoding="utf-8") as stream:
        for line in stream:
            source = json.loads(line)
            row = records.pop(source["alert_id"])
            assert json.loads(row[0]) == source["evidence"]
            assert row[1:] == (
                source["rule_name"],
                source["source_product"],
                source["mitre"]["tactic"],
                source["mitre"]["technique_id"],
                source["mitre"]["technique"],
                source["runbook"],
            )
            assert events[source["alert_id"]] == source["related_events"]
    assert records == {}


@pytest.mark.integration
def test_ingestion_does_not_create_triage_results(loaded_db):
    assert loaded_db.execute("SELECT COUNT(*) FROM alert_history").fetchone()[0] == 0


@pytest.mark.integration
def test_nested_mail_and_ai_values_remain_queryable(loaded_db):
    assert loaded_db.execute("SELECT COUNT(*) FROM email_attachment_contents").fetchone()[0] == 1
    assert (
        loaded_db.execute("SELECT COUNT(*) FROM ai_tool_calls WHERE json_valid(arguments_json)").fetchone()[0] == 7222
    )
    assert loaded_db.execute("SELECT COUNT(*) FROM alert_indicators WHERE value='10.40.16.21-26'").fetchone()[0] == 0
    assert (
        loaded_db.execute(
            "SELECT COUNT(*) FROM alert_indicators WHERE value BETWEEN '10.40.16.21' AND '10.40.16.26'"
        ).fetchone()[0]
        >= 6
    )
