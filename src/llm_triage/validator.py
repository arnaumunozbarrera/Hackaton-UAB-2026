"""Validation of the ticket returned by the LLM.

Why: the triage output must always have the same format (ticket_salida.schema.json) and must respect the SOC
policy, whatever the model writes. Errors are returned as short sentences so they can be sent back to the model
for a correction attempt and shown in the UI.
"""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator

from ..severity import SEVERITY_FIELDS

# Actions that always need N2 (or higher) approval in politica_soc.md section 4.
APPROVAL_KEYWORDS = (
    "aislar", "isolate", "deshabilitar", "disable", "revocar", "revoke", "reset", "restablecer", "contraseña",
    "password", "desactivar", "clave", "access_key",
)  # fmt: skip
OT_MARKERS = ("plc-", "hmi-", "logistics-ot", " ot ", "red ot")
SEVERE = ("high", "critical")


def _schema_errors(ticket: Any, schema: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(ticket), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '(raíz)'}: {e.message}" for e in errors]


def _policy_errors(ticket: dict[str, Any], alert_id: str) -> list[str]:
    errors = []
    if alert_id not in ticket.get("alert_ids", []):
        errors.append(f"alert_ids debe incluir {alert_id}")
    for i, action in enumerate(ticket.get("recommended_actions", [])):
        text = f" {action.get('action', '')} {action.get('target', '')} ".lower()
        if any(k in text for k in APPROVAL_KEYWORDS) and not action.get("requires_approval"):
            errors.append(
                f"recommended_actions/{i}: '{action.get('action')}' requiere aprobación (política, apartado 4)"
            )
        if any(m in text for m in OT_MARKERS) and "escal" not in text:
            errors.append(f"recommended_actions/{i}: sobre OT solo se puede escalar")
    if ticket.get("executed_actions"):
        errors.append("executed_actions debe estar vacío: el LLM solo propone")
    severe_tp = ticket.get("verdict") == "true_positive" and ticket.get("severity") in SEVERE
    if severe_tp and not (ticket.get("escalation") or {}).get("escalate"):
        errors.append("un true_positive high o critical exige escalation.escalate = true (política, apartado 5)")
    return errors


def validate_ticket(ticket: Any, schema: dict[str, Any], alert_id: str) -> list[str]:
    """All format and policy errors of a ticket (empty list = valid)."""
    errors = _schema_errors(ticket, schema)
    if isinstance(ticket, dict):
        errors += _policy_errors(ticket, alert_id)
    return errors


def tool_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Model-owned ticket fields only; severity is completed by the server before validation."""
    output = {k: v for k, v in schema.items() if k not in ("$schema", "title")}
    output["properties"] = {k: v for k, v in schema["properties"].items() if k not in SEVERITY_FIELDS}
    output["required"] = [k for k in schema.get("required", []) if k not in SEVERITY_FIELDS]
    output["additionalProperties"] = False
    return output
