"""Server-owned severity fields. Model output cannot set or adjust the matrix result."""

from __future__ import annotations

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
