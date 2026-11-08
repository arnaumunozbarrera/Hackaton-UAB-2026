"""Append severity justifications with frozen inputs, relational evidence and policy identity."""

from __future__ import annotations

import json
import sqlite3
from typing import Any


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


def append_assessment(
    conn: sqlite3.Connection, alert_id: str, ticket: dict[str, Any], assessment: dict[str, Any], assessed_at: str
) -> int:
    """Participates in the ticket transaction; never commits or overwrites an earlier assessment."""
    if assessment["alert_id"] != alert_id:
        raise ValueError("La evaluación corresponde a otra alerta")
    if (assessment["final_severity"], assessment["verdict"], assessment["rationale"]) != (
        ticket.get("severity"),
        ticket.get("verdict"),
        ticket.get("severity_rationale"),
    ):
        raise ValueError("La evaluación de severidad no coincide con el ticket")
    if not assessment.get("evidence"):
        raise ValueError("La evaluación de severidad necesita evidencias")
    row = conn.execute(
        "INSERT INTO severity_assessments (alert_id,rule_severity,criticality,base_severity,adjustment,final_severity,"
        "verdict,method,rationale,rules_version,policy_hash,input_snapshot_json,observation_start,observation_end,assessed_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            alert_id,
            assessment["rule_severity"],
            assessment["criticality"],
            assessment["base_severity"],
            assessment["adjustment"],
            assessment["final_severity"],
            assessment["verdict"],
            assessment["method"],
            assessment["rationale"],
            assessment["rules_version"],
            assessment["policy_hash"],
            _json(assessment["input_snapshot"]),
            assessment.get("observation_start"),
            assessment.get("observation_end"),
            assessed_at,
        ),
    )
    assessment_id = row.lastrowid
    for evidence in assessment["evidence"]:
        source, key = evidence["source"], evidence.get("source_key")
        asset = (
            conn.execute("SELECT asset_id FROM assets WHERE hostname=?", (key,)).fetchone()
            if source == "assets"
            else None
        )
        service = (
            conn.execute("SELECT service_id FROM business_services WHERE name=?", (key,)).fetchone()
            if source == "business_services"
            else None
        )
        reference = evidence["reference"]
        # Scope provenance starts with an event ID when the relationship came from a cited log.
        candidate = reference.split(";", 1)[0]
        event = evidence.get("event_id")
        if event is None and source == "criticality_scope":
            matched = conn.execute("SELECT event_id FROM logs WHERE event_id=?", (candidate,)).fetchone()
            event = matched[0] if matched else None
        change = evidence.get("change_id")
        if change is None and source == "alert_log_selection":
            matched = conn.execute("SELECT change_id FROM changes WHERE change_id=?", (reference,)).fetchone()
            change = matched[0] if matched else None
        conn.execute(
            "INSERT INTO severity_evidence (assessment_id,condition,status,source,source_key,event_id,change_id,"
            "asset_id,service_id,reference,finding,details_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                assessment_id,
                evidence["condition"],
                evidence["status"],
                source,
                key,
                event,
                change,
                asset[0] if asset else None,
                service[0] if service else None,
                reference,
                evidence["finding"],
                _json(evidence.get("details", {})),
            ),
        )
    return assessment_id


def history(conn: sqlite3.Connection, alert_id: str) -> list[dict[str, Any]]:
    cursor = conn.execute(
        "SELECT * FROM severity_assessments WHERE alert_id=? ORDER BY assessment_id DESC", (alert_id,)
    )
    columns = [column[0] for column in cursor.description]
    assessments = [dict(zip(columns, row, strict=True)) for row in cursor]
    for assessment in assessments:
        assessment["input_snapshot"] = json.loads(assessment.pop("input_snapshot_json"))
        cursor = conn.execute(
            "SELECT * FROM severity_evidence WHERE assessment_id=? ORDER BY evidence_id", (assessment["assessment_id"],)
        )
        columns = [column[0] for column in cursor.description]
        evidence = [dict(zip(columns, row, strict=True)) for row in cursor]
        for item in evidence:
            item["details"] = json.loads(item.pop("details_json"))
        assessment["evidence"] = evidence
    return assessments
