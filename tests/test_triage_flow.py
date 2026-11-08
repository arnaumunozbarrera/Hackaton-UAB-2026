"""Triage flow: discriminator, ticket store, similarity, DB backend and, with a database, the full pipeline."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
from pathlib import Path

import numpy as np
import pytest

from src.database.enrich import PIPELINE_SQL
from src.embeddings.encoder import HashingEncoder
from src.llm_triage.db_backend import DbToolBackend
from src.prompt_builder.db_context import StoredSelection
from src.triage_flow import discriminator, similarity, store

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = (
    json.loads((ROOT / "docs/01_contexto/ticket_salida.schema.json").read_text(encoding="utf-8"))
    if (ROOT / "docs/01_contexto/ticket_salida.schema.json").exists()
    else None
)


def mini_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE detection_rules (rule_id TEXT PRIMARY KEY, name TEXT, source_product TEXT, tactic TEXT, runbook_id TEXT);
        CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, created_at TEXT, rule_id TEXT, severity TEXT);
        CREATE TABLE alert_events (alert_id TEXT, position INTEGER, event_id TEXT);
        CREATE TABLE alert_history (alert_id TEXT PRIMARY KEY, verdict TEXT NOT NULL);
        CREATE TABLE alert_enriched (alert_id TEXT PRIMARY KEY, rule_severity TEXT, matrix_base_severity TEXT,
            is_ot INTEGER, technique_id TEXT, rule_id TEXT);
        INSERT INTO detection_rules VALUES ('R1', 'Regla de prueba', 'NGFW', 'Discovery', 'RB-01');
        """
    )
    conn.executescript(
        PIPELINE_SQL.read_text(encoding="utf-8").replace(
            'FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id")', "CHECK (1)"
        )
    )
    return conn


def add_alert(conn, aid, states, severity="low", base="low", is_ot=0):
    conn.execute("INSERT INTO alerts VALUES (?, '2026-10-05T10:00:00.000Z', 'R1', ?)", (aid, severity))
    conn.execute("INSERT INTO alert_enriched VALUES (?, ?, ?, ?, 'T1000', 'R1')", (aid, severity, base, is_ot))
    for i, (state, reason, ref) in enumerate(states):
        conn.execute("INSERT INTO alert_events VALUES (?, ?, ?)", (aid, i, f"EV-{aid}-{i}"))
        conn.execute(
            "INSERT INTO alert_log_selection VALUES (?, ?, 'firewall', '2026-10-05T09:59:00.000Z', ?, ?, ?)",
            (aid, f"EV-{aid}-{i}", state, reason, ref),
        )


# ------------------------------------------------------------------------------------------------ discriminator
def test_discriminator_closes_only_fully_explained_alerts():
    conn = mini_db()
    add_alert(conn, "A1", [("N4", "explained:A_cambio_aprobado", "CHG-1"), ("N1", None, None)])
    add_alert(conn, "A2", [("N4", "explained:C_escaner", "geoip"), ("kept", "unexplained", None)])
    add_alert(conn, "A3", [("N3", None, None)])
    add_alert(conn, "A4", [("N4", "explained:A_cambio_aprobado", "CHG-1")], severity="high")
    add_alert(conn, "A5", [("N4", "explained:B_regla_empresa", "OT")], is_ot=1)
    add_alert(conn, "A6", [("N4", "explained:C_escaner_bloqueado", "geoip")])
    routes = {a: discriminator.decide(conn, a).route for a in ("A1", "A2", "A3", "A4", "A5", "A6", "missing")}
    assert routes == {"A1": "discriminator", "A2": "llm", "A3": "llm", "A4": "llm", "A5": "llm",
                      "A6": "discriminator", "missing": "llm"}  # fmt: skip
    assert discriminator.decide(conn, "A1").ticket["verdict"] == "benign_true_positive"
    assert discriminator.decide(conn, "A6").ticket["verdict"] == "false_positive"


@pytest.mark.skipif(SCHEMA is None, reason="docs/ not available")
def test_discriminator_ticket_is_schema_and_policy_valid():
    from src.llm_triage.validator import validate_ticket

    conn = mini_db()
    add_alert(conn, "A1", [("N4", "explained:A_cambio_aprobado", "CHG-2026-1042")])
    ticket = discriminator.decide(conn, "A1").ticket
    assert validate_ticket(ticket, SCHEMA, "A1") == []
    assert "CHG-2026-1042" in ticket["summary"] and ticket["executed_actions"] == []


# ------------------------------------------------------------------------------------------------ store
def test_store_queue_decision_and_history():
    conn = mini_db()
    for aid, sev, route in (("A1", "low", "llm"), ("A2", "critical", "llm"), ("A3", "informational", "discriminator")):
        add_alert(conn, aid, [("kept", "unexplained", None)])
        ticket = {"verdict": "true_positive", "severity": sev, "confidence": 0.9, "escalation": {"escalate": False}}
        store.save_ticket(conn, aid, ticket, valid=True, route=route, model="test")
    assert [t["alert_id"] for t in store.queue(conn)] == ["A2", "A1"]  # criticality order, auto-closed excluded
    out = store.decide(conn, "A2", "approve", "ok", "tester")
    assert out["history_written"] and conn.execute("SELECT verdict FROM alert_history").fetchone()[0] == "true_positive"
    assert [t["alert_id"] for t in store.queue(conn)] == ["A1"]
    assert {t["alert_id"] for t in store.history(conn)} == {"A2", "A3"}
    with pytest.raises(ValueError):
        store.decide(conn, "A1", "delete")
    with pytest.raises(KeyError):
        store.decide(conn, "nope", "approve")


def test_selection_round_trip():
    conn = mini_db()
    add_alert(conn, "A1", [("kept", "open_text:A_cambio_aprobado", "CHG-1"), ("N4", "explained:D_sandbox", "SBX"),
                           ("kept", "guard:G1_ioc", None), ("N2", None, None)])  # fmt: skip
    sel = StoredSelection.load(conn)
    assert [r.event_id for r in sel.kept_for_alert("A1")] == ["EV-A1-0", "EV-A1-2"]
    assert sel.open_text_kept["EV-A1-0"].reference == "CHG-1" and sel.guarded["EV-A1-2"] == "G1_ioc"
    assert sel.discarded == {"EV-A1-1": "N4", "EV-A1-3": "N2"} and sel.explanations["EV-A1-1"].reference == "SBX"


# ------------------------------------------------------------------------------------------------ embeddings
def test_hashing_encoder_is_deterministic_and_normalised():
    enc = HashingEncoder(256)
    a, b = enc.encode(["rule_id: UC-WEB-001 PHP Injection", "rule_id: UC-WEB-001 PHP Injection"])
    assert np.allclose(a, b) and abs(float(np.linalg.norm(a)) - 1) < 1e-5
    c = enc.encode(["rule_id: UC-EDR-002 PowerShell"])[0]
    assert float(a @ c) < float(a @ b)


def test_similar_resolved_uses_only_resolved_alerts():
    conn = mini_db()
    alerts = {}
    for aid, text in (
        ("A1", "PHP injection waf"),
        ("A2", "PHP injection waf"),
        ("A3", "PHP injection waf"),
        ("A4", "x"),
    ):
        add_alert(conn, aid, [])
        alerts[aid] = {"alert_id": aid, "rule_id": "R1", "description": text}
    assert similarity.index_alerts(conn, alerts, HashingEncoder(128)) == 4
    assert similarity.similar_resolved(conn, "A1") == []  # nothing resolved yet
    store.save_ticket(conn, "A2", {"verdict": "false_positive", "severity": "low"}, valid=True, route="llm")
    store.save_ticket(conn, "A3", {"verdict": "needs_more_info", "severity": "low"}, valid=True, route="llm")
    out = similarity.similar_resolved(conn, "A1")
    assert [s["alert_id"] for s in out] == ["A2"] and out[0]["verdict"] == "false_positive"


# ------------------------------------------------------------------------------------------------ backend
def test_db_backend_normalises_parameters():
    assert DbToolBackend.normalise("user_profile", ["TARVIA\\Carmen.Sala"]) == ["carmen.sala"]
    assert DbToolBackend.normalise("indicator", ["Evil.EXAMPLE"]) == ["evil.example"]
    assert DbToolBackend.normalise("host_activity", ["WS-BCN-1", "a", "b"]) == ["WS-BCN-1", "a", "b"]


# ------------------------------------------------------------------------------------------------ integration
def _db() -> Path | None:
    path = Path(os.environ.get("TARVIA_DB") or ROOT / "data" / "tarvia.sqlite")
    return path if path.exists() else None


@pytest.fixture(scope="module")
def flow(tmp_path_factory):
    source = _db()
    if source is None or not (ROOT / "docs").exists():
        pytest.skip("requires the ingested database and docs/")
    target = tmp_path_factory.mktemp("db") / "tarvia.sqlite"
    shutil.copyfile(source, target)
    from src.triage_flow import TriageFlow

    os.environ.setdefault("TARVIA_EMBEDDING_BACKEND", "hashing")
    f = TriageFlow(target, ROOT / "docs", "mock", progress=lambda m: None)
    yield f
    f.close()


@pytest.mark.integration
def test_every_catalogue_query_runs_on_the_database(flow):
    from src.prompt_builder.schema import QUERIES

    aid = flow.pending(1)[0]
    package = flow.builder.build(aid)
    for q in package.queries:
        if q.example is not None:
            flow.backend.execute(q.name, q.example)  # raises on any missing view or column
    assert set(QUERIES) >= {q.name for q in package.queries}


@pytest.mark.integration
def test_pipeline_routes_and_persists(flow):
    ids = flow.pending(5)
    auto = flow.conn.execute(
        "SELECT a.alert_id FROM alerts a WHERE NOT EXISTS (SELECT 1 FROM alert_log_selection s WHERE s.alert_id = "
        "a.alert_id AND s.state NOT IN ('N1','N4')) AND EXISTS (SELECT 1 FROM alert_log_selection s WHERE "
        "s.alert_id = a.alert_id AND s.state = 'N4') AND a.severity IN ('low','medium') LIMIT 1"
    ).fetchone()[0]
    summary = flow.run_batch(alert_ids=ids + [auto])
    assert summary["errors"] == 0 and summary["invalid"] == 0
    assert store.get_ticket(flow.conn, auto)["route"] == "discriminator"
    assert all(store.get_ticket(flow.conn, a)["route"] == "llm" for a in ids)  # high/critical first
    assert flow.conn.execute("SELECT COUNT(*) FROM alert_log_selection").fetchone()[0] > 0
    stats = store.stats(flow.conn)
    assert stats["alerts_triaged"] >= 6 and stats["embeddings"] == stats["alerts_total"]


def test_live_copy_keeps_logs_and_drops_alerts(tmp_path):
    from src.database.live import create_live

    source = tmp_path / "src.sqlite"
    conn = sqlite3.connect(source)
    conn.executescript(
        "CREATE TABLE logs (event_id TEXT PRIMARY KEY); CREATE TABLE alerts (alert_id TEXT PRIMARY KEY);"
        "CREATE TABLE alert_events (alert_id TEXT, event_id TEXT); CREATE TABLE triage_tickets (alert_id TEXT);"
        "INSERT INTO logs VALUES ('E1'); INSERT INTO alerts VALUES ('A1'); INSERT INTO alert_events VALUES ('A1','E1');"
        "INSERT INTO triage_tickets VALUES ('A1');"
    )
    conn.commit()
    conn.close()
    out = tmp_path / "live.sqlite"
    removed = create_live(source, out)
    live = sqlite3.connect(out)
    assert removed["alerts"] == 1 and live.execute("SELECT COUNT(*) FROM logs").fetchone()[0] == 1
    assert live.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    assert live.execute("SELECT COUNT(*) FROM triage_tickets").fetchone()[0] == 0
    with pytest.raises(FileExistsError):
        create_live(source, out)
