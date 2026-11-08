"""Severity decisions retain factual inputs, evidence and previous assessment versions."""

import copy
import sqlite3

import pytest

from src.database.live import create_live
from src.severity import apply_matrix_severity, assessment_for_ticket
from src.triage_flow import severity_audit, store
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
