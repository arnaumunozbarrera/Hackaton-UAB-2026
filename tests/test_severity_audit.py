"""Severity decisions retain factual inputs, evidence and previous assessment versions."""

import copy
import sqlite3
import threading

import pytest

from src.database.live import create_live
from src.prompt_builder import DbContextSource, PromptBuilder
from src.severity import apply_matrix_severity, assessment_for_ticket
from src.triage_flow import severity_audit, store
from src.triage_flow.automation import PolicyAutomation
from src.triage_flow.flow import TriageFlow
from tests import test_criticality
from tests.test_criticality import both_paths

db = test_criticality.db


def calculation(conn):
    _, package, _ = both_paths(conn)
    body = apply_matrix_severity(
        {
            "ticket_id": "T-A1",
            "alert_ids": ["A1"],
            "title": "Test",
            "verdict": "needs_more_info",
            "confidence": 0.5,
            "summary": "Pending investigation",
            "evidence": [],
            "recommended_actions": [],
            "escalation": {"escalate": False},
        },
        package.metadata,
    )
    return body, assessment_for_ticket(package.metadata, body)


def save(conn, body, assessment, valid=True):
    store.save_ticket(conn, "A1", body, valid=valid, route="llm", model="mock", severity_assessment=assessment)


def test_valid_ticket_persists_assessment_inputs_and_relational_evidence(db):
    body, assessment = calculation(db)
    save(db, body, assessment)
    saved = store.get_ticket(db, "A1")["severity_assessments"][0]
    assert saved["alert_id"] == "A1" and saved["base_severity"] == saved["final_severity"] == "high"
    assert saved["adjustment"] == 0 and saved["method"] == "matrix"
    assert len(saved["policy_hash"]) == 64 and saved["rules_version"] == "matrix-v1"
    assert saved["observation_start"] is None and saved["observation_end"] is None
    assert saved["input_snapshot"]["criticality_inputs"]["services"]
    assert any(e["asset_id"] == "H1" for e in saved["evidence"])
    assert any(e["service_id"] == 2 and e["details"]["criticality"] == "Crítica" for e in saved["evidence"])
    assert any(e["condition"] == "matrix_lookup" for e in saved["evidence"])
    assert any(e["condition"] == "severity_adjustments" and e["status"] == "not_evaluated" for e in saved["evidence"])
    assert db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_retriage_preserves_prior_justification_and_inventory_snapshot(db):
    body, assessment = calculation(db)
    save(db, body, assessment)
    old = severity_audit.history(db, "A1")[0]
    db.execute("UPDATE business_services SET criticality='Baja' WHERE service_id=2")
    body, assessment = calculation(db)
    save(db, body, assessment)
    history = severity_audit.history(db, "A1")
    assert len(history) == 2 and history[0]["assessment_id"] > history[1]["assessment_id"]
    assert history[0]["final_severity"] == "medium" and history[1]["final_severity"] == "high"
    assert history[1] == old
    assert store.get_ticket(db, "A1")["ticket"]["severity"] == "medium"


def test_failed_ticket_does_not_record_a_final_severity_decision(db):
    body, assessment = calculation(db)
    save(db, body, assessment, valid=False)
    assert severity_audit.history(db, "A1") == []


@pytest.mark.parametrize("corrupt", ["alert_id", "final_severity", "evidence"])
def test_contradictory_or_unjustified_assessment_rolls_back_ticket(db, corrupt):
    body, assessment = calculation(db)
    save(db, body, assessment)
    before = store.get_ticket(db, "A1")
    bad = copy.deepcopy(assessment)
    bad[corrupt] = {"alert_id": "other", "final_severity": "low", "evidence": []}[corrupt]
    with pytest.raises(ValueError):
        save(db, body, bad)
    assert store.get_ticket(db, "A1") == before


def test_evidence_foreign_key_error_rolls_back_ticket_and_assessment(db):
    body, assessment = calculation(db)
    save(db, body, assessment)
    before = store.get_ticket(db, "A1")
    bad = copy.deepcopy(assessment)
    bad["evidence"][0]["event_id"] = "MISSING-EVENT"
    with pytest.raises(sqlite3.IntegrityError):
        save(db, body, bad)
    assert store.get_ticket(db, "A1") == before


def test_discriminator_exception_is_not_misrepresented_as_a_one_level_adjustment(db):
    body, assessment = calculation(db)
    body = body | {
        "severity": "informational",
        "severity_rationale": "Existing context-based closure",
        "verdict": "benign_true_positive",
    }
    assessment.update(
        final_severity="informational",
        rationale=body["severity_rationale"],
        verdict=body["verdict"],
        method="discriminator",
        adjustment=None,
        rules_version="discriminator-v1",
    )
    db.execute("INSERT INTO changes(change_id,title) VALUES ('CHG-1','Approved test change')")
    db.execute("INSERT INTO logs VALUES ('E1','2026-10-10T10:00:00Z','vpn')")
    assessment["evidence"].append(
        {
            "condition": "existing_discriminator_context",
            "status": "confirmed",
            "source": "alert_log_selection",
            "event_id": "E1",
            "reference": "CHG-1",
            "finding": "Context referenced by the discriminator",
            "details": {},
        }
    )
    store.save_ticket(db, "A1", body, valid=True, route="discriminator", severity_assessment=assessment)
    saved = severity_audit.history(db, "A1")[0]
    assert saved["base_severity"] == "high" and saved["final_severity"] == "informational"
    assert saved["adjustment"] is None and saved["method"] == "discriminator"
    assert any(e["event_id"] == "E1" and e["change_id"] == "CHG-1" for e in saved["evidence"])


def test_matrix_assessment_cannot_claim_a_different_final_result(db):
    body, assessment = calculation(db)
    body["severity"] = assessment["final_severity"] = "low"
    db.commit()
    with pytest.raises(sqlite3.IntegrityError):
        save(db, body, assessment)
    assert severity_audit.history(db, "A1") == []
    assert store.get_ticket(db, "A1") is None


def test_live_copy_clears_assessments_before_alerts_without_changing_original(db, tmp_path):
    body, assessment = calculation(db)
    save(db, body, assessment)
    source, target = tmp_path / "original.sqlite", tmp_path / "live.sqlite"
    with sqlite3.connect(source) as copied:
        db.backup(copied)
    removed = create_live(source, target)
    assert removed["severity_assessments"] == 1 and removed["severity_evidence"] > 0
    with sqlite3.connect(target) as live:
        assert live.execute("SELECT count(*) FROM severity_assessments").fetchone()[0] == 0
        assert live.execute("PRAGMA foreign_key_check").fetchall() == []
    assert len(severity_audit.history(db, "A1")) == 1


def test_duplicate_pins_the_original_assessment_even_after_parent_retriage(db):
    db.execute("UPDATE alerts SET severity='low' WHERE alert_id='A1'")
    db.execute(
        "INSERT INTO alerts(alert_id,created_at,rule_id,severity) VALUES ('A2','2026-10-10T10:01:00Z','R1','low')"
    )
    db.execute("INSERT INTO alert_assets VALUES ('A2','H1')")
    db.execute("INSERT INTO logs VALUES ('E1','2026-10-10T10:00:00Z','vpn')")
    db.execute("INSERT INTO alert_events VALUES ('A1',0,'E1')")
    db.execute(
        "INSERT INTO alert_log_selection VALUES ('A1','E1','vpn','2026-10-10T10:00:00Z','N4','explained:A_cambio_aprobado','CHG-1')"
    )
    both_paths(db)
    # The actual flow is exercised against the in-memory database, without preparation or model calls.
    flow = TriageFlow.__new__(TriageFlow)
    flow.conn, flow.lock = db, threading.RLock()
    flow.source = DbContextSource(db)
    flow.builder = PromptBuilder(flow.source)
    flow.policy = PolicyAutomation(auto_containment=False)
    assert flow.triage("A1")["route"] == "discriminator"
    original = severity_audit.history(db, "A1")[0]
    assert flow.triage("A2")["route"] == "discriminator"
    child = severity_audit.history(db, "A2")[0]
    inherited = next(e for e in child["evidence"] if e["condition"] == "inherited_decision")
    assert inherited["status"] == "confirmed" and inherited["source"] == "severity_assessments"
    assert inherited["source_key"] == str(original["assessment_id"])
    assert inherited["details"]["source_alert_id"] == "A1"
    assert inherited["details"]["source_assessment_id"] == original["assessment_id"]
    assert inherited["details"]["grouping_reason"]
    assert not any(e["condition"] == "existing_discriminator_context" for e in child["evidence"])

    db.execute("UPDATE alerts SET severity='high' WHERE alert_id='A1'")
    body, assessment = calculation(db)
    save(db, body, assessment)
    assert severity_audit.history(db, "A1")[0]["assessment_id"] != original["assessment_id"]
    assert severity_audit.history(db, "A1")[0]["final_severity"] == "critical"
    assert severity_audit.history(db, "A2")[0] == child
    linked = db.execute(
        "SELECT alert_id,final_severity FROM severity_assessments WHERE assessment_id=?",
        (inherited["details"]["source_assessment_id"],),
    ).fetchone()
    assert linked == ("A1", child["final_severity"])


@pytest.mark.parametrize("corrupt", ["source_alert_id", "source_assessment_id", "source_key"])
def test_inconsistent_parent_reference_is_rejected_atomically(db, corrupt):
    body, assessment = calculation(db)
    save(db, body, assessment)
    db.execute(
        "INSERT INTO alerts(alert_id,created_at,rule_id,severity) VALUES ('A2','2026-10-10T10:01:00Z','R1','medium')"
    )
    evidence = severity_audit.inherited_decision_evidence(db, "A1", body)
    child = copy.deepcopy(assessment)
    child.update(alert_id="A2", method="discriminator", adjustment=None)
    child["evidence"].append(evidence)
    if corrupt == "source_key":
        evidence["source_key"] = "99999"
    else:
        evidence["details"][corrupt] = "OTHER" if corrupt == "source_alert_id" else 99999
    db.commit()
    with pytest.raises(ValueError):
        store.save_ticket(
            db, "A2", body | {"alert_ids": ["A1", "A2"]}, valid=True, route="discriminator", severity_assessment=child
        )
    assert severity_audit.history(db, "A2") == []
    assert store.get_ticket(db, "A2") is None


def test_legacy_or_mismatching_parent_audit_is_explicit_and_snapshot_is_frozen(db):
    body, assessment = calculation(db)
    save(db, body, assessment)
    changed = body | {"severity": "low"}
    evidence = severity_audit.inherited_decision_evidence(db, "A1", changed)
    assert evidence["source"] == "triage_tickets" and evidence["status"] == "unknown"
    assert evidence["details"]["source_assessment_id"] is None
    changed["severity"] = "critical"
    assert evidence["details"]["source_ticket_snapshot"]["severity"] == "low"


def test_source_version_is_pinned_before_the_duplicate_is_saved(db):
    body, assessment = calculation(db)
    body["verdict"] = assessment["verdict"] = "benign_true_positive"
    save(db, body, assessment)
    origin = severity_audit.history(db, "A1")[0]
    db.execute(
        "INSERT INTO alerts(alert_id,created_at,rule_id,severity) VALUES ('A2','2026-10-10T10:01:00Z','R1','medium')"
    )
    child = copy.deepcopy(assessment)
    child.update(alert_id="A2", method="discriminator", adjustment=None)
    child["evidence"].append(severity_audit.inherited_decision_evidence(db, "A1", body))

    # A1 gets another valid assessment after the duplicate's source was selected, before A2 is stored.
    later_body = body | {"verdict": "needs_more_info"}
    later_assessment = copy.deepcopy(assessment)
    later_assessment["verdict"] = "needs_more_info"
    save(db, later_body, later_assessment)
    store.save_ticket(
        db, "A2", body | {"alert_ids": ["A1", "A2"]}, valid=True, route="discriminator", severity_assessment=child
    )

    inherited = next(
        e for e in severity_audit.history(db, "A2")[0]["evidence"] if e["condition"] == "inherited_decision"
    )
    assert inherited["details"]["source_assessment_id"] == origin["assessment_id"]
    assert inherited["details"]["source_assessment_id"] != severity_audit.history(db, "A1")[0]["assessment_id"]
