"""Append severity justifications with frozen inputs, relational evidence and policy identity."""

from __future__ import annotations

import json
import sqlite3
from copy import deepcopy
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
    for evidence in assessment["evidence"]:
        if evidence["condition"] != "inherited_decision" or evidence["source"] != "severity_assessments":
            continue
        details = evidence["details"]
        parent = conn.execute(
            "SELECT alert_id,final_severity,verdict,rationale FROM severity_assessments WHERE assessment_id=?",
            (details["source_assessment_id"],),
        ).fetchone()
        expected = (
            details["source_alert_id"],
            ticket.get("severity"),
            ticket.get("verdict"),
            ticket.get("severity_rationale"),
        )
        if parent is None or tuple(parent) != expected or parent[0] == alert_id:
            raise ValueError("La decisión heredada no coincide con la evaluación de origen")
        if evidence.get("source_key") != str(details["source_assessment_id"]):
            raise ValueError("La referencia a la evaluación de origen es incoherente")
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


def history(conn: sqlite3.Connection, alert_id: str, limit: int | None = None) -> list[dict[str, Any]]:
    query = "SELECT * FROM severity_assessments WHERE alert_id=? ORDER BY assessment_id DESC"
    params = (alert_id,)
    if limit is not None:
        query += " LIMIT ?"
        params = (alert_id, limit)
    cursor = conn.execute(query, params)
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


def inherited_decision_evidence(conn: sqlite3.Connection, parent_id: str, ticket: dict[str, Any]) -> dict[str, Any]:
    """Pin the assessment selected with the parent ticket, before the parent can be re-triaged."""
    latest = history(conn, parent_id, limit=1)
    parent = latest[0] if latest else None
    matches = parent is not None and (parent["final_severity"], parent["verdict"], parent["rationale"]) == (
        ticket.get("severity"),
        ticket.get("verdict"),
        ticket.get("severity_rationale"),
    )
    details = {
        "source_alert_id": parent_id,
        "source_assessment_id": parent["assessment_id"] if matches else None,
        "source_ticket_snapshot": deepcopy(ticket),
        "grouping_reason": "Misma regla, entidades y día; decisión de origen resuelta como falsa o benigna.",
    }
    if matches:
        details["source_assessment_snapshot"] = {k: v for k, v in parent.items() if k != "evidence"}
    return {
        "condition": "inherited_decision",
        "status": "confirmed" if matches else "unknown",
        "source": "severity_assessments" if matches else "triage_tickets",
        "source_key": str(parent["assessment_id"]) if matches else parent_id,
        "reference": f"severity_assessments.assessment_id={parent['assessment_id']}"
        if matches
        else f"triage_tickets.alert_id={parent_id}",
        "finding": (
            f"Decisión heredada de {parent_id}, evaluación {parent['assessment_id']}."
            if matches
            else f"Decisión heredada de {parent_id}; no hay una evaluación de auditoría coincidente. Se conserva copia del ticket de origen."
        ),
        "details": details,
    }
