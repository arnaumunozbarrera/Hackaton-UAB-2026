"""Focused contract tests for the read-only LLM context boundary."""

import hashlib
import sqlite3

from db import build_db
from db.triage_context import ContextManager, validate_llm_response


def _fixture(path):
    con = sqlite3.connect(path)
    con.executescript(build_db.DDL + build_db.INDEXES + build_db.VIEWS)
    con.executescript(
        """
        INSERT INTO dim_rule(rule_id,nombre,runbook) VALUES ('R1','PowerShell','RB-02');
        INSERT INTO dim_user(user_key,user_id,username,upn,department,privileged,vip) VALUES ('marta.puig','U1','MARTA.PUIG','marta.puig@tarvia.example','IT',0,0);
        INSERT INTO dim_vulnerability(hostname,criticality,criticality_level,business_service) VALUES ('WS-1','Media',2,'Ecom');
        INSERT INTO dim_context(context_key,context_type,reputation) VALUES ('10.0.0.1','ip',NULL);
        INSERT INTO fact_alert(alert_id,created_at,rule_id,technique_id,user_key,hostname,context_key,source_product,rule_name,rule_severity,mitre_tactic,runbook,entities,evidence)
          VALUES ('A1','2026-10-05 07:56','R1',NULL,'marta.puig','WS-1','10.0.0.1','EDR','PowerShell','medium','Execution','RB-02','[]','{}');
        INSERT INTO bridge_alert_entity(alert_id,entity_type,entity_value,user_key,hostname,context_key) VALUES ('A1','user','marta.puig','marta.puig',NULL,NULL);
        """
    )
    con.commit()
    con.close()


def test_context_is_normalised_validated_and_read_only(tmp_path):
    db = tmp_path / "fixture.sqlite"
    _fixture(db)
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    raw = {"alert_id": "INPUT", "created_at": "2026-10-05T07:56:30.000Z", "rule_id": "R1", "severity": "medium", "runbook": "RB-02", "entities": {"users": [{"upn": "marta.puig@tarvia.example"}], "hosts": [{"hostname": "WS-1"}], "ips": ["10.0.0.1"]}, "mitre": {"tactic": "Execution"}, "related_events": []}
    package = ContextManager(db).build(raw)
    assert package["meta"]["window_alert_hours"] == 24
    assert package["input_alert"]["normalised"]["created_at"] == "2026-10-05 07:56"
    assert package["input_alert"]["resolved_entities"][0]["user_key"] == "marta.puig"
    validate_llm_response({"verdict": "needs_more_info", "final_severity": "medium", "severity_rationale": "unknown", "confidence": 0.1, "action": "review", "escalate_n2": False, "referenced_alert_ids": [], "referenced_event_ids": [], "open_questions": []})
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    con = ContextManager(db).connect()
    try:
        try:
            con.execute("UPDATE dim_user SET vip=1 WHERE user_key=?", ("marta.puig",))
        except sqlite3.DatabaseError:
            pass
        else:
            raise AssertionError("read-only authorizer permitted UPDATE")
    finally:
        con.close()
