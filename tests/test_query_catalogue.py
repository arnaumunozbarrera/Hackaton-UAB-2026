"""Every catalogue query runs on the real schema, read-only, with the documented parameters."""

import re
import sqlite3

import pytest

from src.llm_triage import DatabaseToolBackend
from src.prompt_builder.schema import QUERIES
from src.prompt_builder.tools import MAX_ROWS

SAMPLES = {
    "alert_id": "ALR-20261009-011791",
    "event_id": "EDR-0005329",
    "user_key": "marta.puig",
    "hostname": "WS-BCN-1770",
    "indicator": "micr0soft-365-billing.example",
    "entity_value": "WS-BCN-1174",
    "window_start": "2026-10-01T00:00:00.000Z",
    "window_end": "2026-11-30T00:00:00.000Z",
    "ip": "10.10.1.185",
    "customer": "C-000000",
    "ref_id": "none",
    "sha256": "9a3171208537ad708648f69a6e2607af6738f804b99aef1709b309abf34773da",
    "rule_id": "UC-EDR-001",
    "rule_severity": "high",
}


@pytest.fixture
def backend(mini_db):
    b = DatabaseToolBackend(mini_db)
    yield b
    b.close()


@pytest.mark.parametrize("name", sorted(QUERIES))
def test_every_query_runs(backend, name):
    spec = QUERIES[name]
    rows = backend.execute(name, [SAMPLES[p] for p in spec.params])
    assert len(rows) <= MAX_ROWS


@pytest.mark.parametrize("name", sorted(QUERIES))
def test_queries_are_explicit_and_parameterised(name):
    sql = re.sub(r"'[^']*'", "''", QUERIES[name].sql)
    assert "SELECT *" not in sql.upper()
    numbers = {int(n) for n in re.findall(r"\?(\d+)", sql)}
    assert numbers == set(range(1, len(QUERIES[name].params) + 1))
    assert not re.search(r"\?(?!\d)", sql), "use numbered ?N placeholders"


def test_core_queries_return_the_alert_and_its_logs(backend):
    enriched = backend.execute("alert_enriched", ["ALR-20261009-011791"])[0]
    assert enriched["rule_id"] == "UC-EDR-001" and enriched["runbook_id"] == "RB-02"
    events = backend.execute("alert_events", ["ALR-20261009-011791"])
    assert [e["position"] for e in events] == list(range(len(events))) and events
    assert backend.execute("host_activity", [events[0]["host"], SAMPLES["window_start"], SAMPLES["window_end"]])
    detail = backend.execute("log_detail", ["EDR-0005329"])[0]
    assert "CcmExec.exe" in detail["detail"]
    assert backend.execute("indicator", ["micr0soft-365-billing.example"])[0]["verdict"] == "malicious"
    assert {r["base_severity"] for r in backend.execute("severity_matrix", ["high"])} == {"medium", "high", "critical"}


def test_hash_and_related_alerts_cross_sources(backend):
    rows = backend.execute("hash_activity", [SAMPLES["sha256"]])
    assert [r["event_id"] for r in rows] == ["EDR-0005329"]
    related = backend.execute(
        "related_alerts", ["WS-BCN-1174", SAMPLES["window_start"], SAMPLES["window_end"], "ALR-20261009-011791"]
    )
    assert "ALR-20261005-000301" in {r["alert_id"] for r in related}


def test_unknown_or_disallowed_queries_and_bad_arity_are_rejected(backend):
    with pytest.raises(ValueError):
        backend.execute("drop_everything", [])
    with pytest.raises(ValueError):
        backend.execute("alert_events", ["A", "B"])
    with pytest.raises(ValueError):
        backend.execute("alert_events", ["A"], allowed=["runbook_text"])


def test_connection_cannot_write(backend):
    with pytest.raises(sqlite3.OperationalError):
        backend.conn.execute("DELETE FROM alerts")
