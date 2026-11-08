"""Server-owned severity fields. Model output cannot set or adjust the matrix result."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

SEVERITY_FIELDS = frozenset(("severity", "severity_rationale"))
SEVERITIES = ("informational", "low", "medium", "high", "critical")


def apply_matrix_severity(ticket: Any, metadata: dict[str, Any]) -> Any:
    """Complete the ticket before schema/policy validation, overriding any supplied severity fields."""
    if not isinstance(ticket, dict):
        return ticket
    severity = metadata.get("base_severity")
    if severity not in SEVERITIES:
        raise ValueError("No se puede finalizar el ticket: severidad de matriz no calculable")
    return ticket | {
        "severity": severity,
        "severity_rationale": metadata["severity_rationale"],
    }


def assessment_for_ticket(metadata: dict[str, Any], ticket: dict[str, Any], method: str = "matrix") -> dict[str, Any]:
    """Snapshot server-owned inputs and evidence, independently of the model's ticket evidence."""
    if method not in ("matrix", "discriminator"):
        raise ValueError("Unsupported assessment method")
    inputs = deepcopy(metadata["criticality_inputs"])
    evidence = []
    for kind, rows, key, table in (
        ("asset_criticality", inputs["assets"], "hostname", "assets"),
        ("service_criticality", inputs["services"], "name", "business_services"),
    ):
        for row in rows:
            name, level = row[key], row["criticality"]
            evidence.append(
                {
                    "condition": kind,
                    "status": "confirmed" if level in ("Baja", "Media", "Alta", "Crítica") else "unknown",
                    "source": table,
                    "source_key": name,
                    "reference": f"{table}.{key}={name}",
                    "finding": f"Criticidad registrada de {name}: {level}",
                    "details": row,
                }
            )
    for relation in inputs.get("relations", []):
        evidence.append(
            {
                "condition": "scope_relationship",
                "status": "confirmed",
                "source": "criticality_scope",
                "source_key": relation["name"],
                "reference": relation["reference"],
                "finding": f"Vínculo documentado: {relation['name']} mediante {relation['relation']}",
                "details": relation,
            }
        )
    evidence.append(
        {
            "condition": "matrix_lookup",
            "status": "confirmed",
            "source": "ref_severity_matrix",
            "source_key": f"{metadata['rule_severity']}|{metadata['criticality']}",
            "reference": "docs/01_contexto/politica_soc.md#2",
            "finding": metadata["severity_rationale"],
            "details": {k: metadata[k] for k in ("rule_severity", "criticality", "base_severity", "matrix_row")},
        }
    )
    evidence.append(
        {
            "condition": "severity_adjustments",
            "status": "not_evaluated",
            "source": "severity_rules",
            "reference": "docs/01_contexto/politica_soc.md#2",
            "finding": "Las reglas de ajuste +1/−1 todavía no se evalúan; no se infiere que sus condiciones sean falsas.",
            "details": {},
        }
    )
    return {
        "alert_id": metadata["alert_id"],
        "rule_severity": metadata["rule_severity"],
        "criticality": metadata["criticality"],
        "base_severity": metadata["base_severity"],
        "adjustment": 0 if method == "matrix" else None,
        "final_severity": ticket["severity"],
        "verdict": ticket.get("verdict"),
        "method": method,
        "rationale": ticket["severity_rationale"],
        "rules_version": f"{method}-v1",
        "policy_hash": metadata["policy_hash"],
        "input_snapshot": {
            "rule_id": metadata["rule_id"],
            "matrix_row": metadata["matrix_row"],
            "criticality_origin": metadata["criticality_origin"],
            "criticality_inputs": inputs,
        },
        "evidence": evidence,
    }
