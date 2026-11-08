"""Build a stable, security-aware text representation of SIEM alerts.

Only fields selected by the application are included. Raw evidence is not dumped into
the embedding because subjects, prompts, URLs and descriptions can be attacker-controlled.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any


def _value(value: Any) -> str:
    """Render a scalar or a small structured value deterministically."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return str(value)


def _entities(alert: dict[str, Any]) -> list[str]:
    """Extract stable entity values without embedding every nested evidence field."""
    rows: list[str] = []
    for kind, values in sorted((alert.get("entities") or {}).items()):
        items = values if isinstance(values, list) else [values]
        for item in items:
            if isinstance(item, dict):
                selected = item.get("upn") or item.get("hostname") or item.get("name") or item.get("ip")
                value = selected if selected is not None else _value(item)
            else:
                value = _value(item)
            if value:
                rows.append(f"{kind}={value}")
    return rows


def canonical_alert_text(alert: dict[str, Any]) -> str:
    """Return the controlled text sent to the embedding model."""
    mitre = alert.get("mitre") or {}
    fields = [
        ("source", alert.get("source_product")),
        ("rule_id", alert.get("rule_id")),
        ("rule_name", alert.get("rule_name")),
        ("rule_severity", alert.get("severity")),
        ("tactic", mitre.get("tactic")),
        ("technique_id", mitre.get("technique_id")),
        ("technique", mitre.get("technique")),
        ("description", alert.get("description")),
    ]
    lines = [f"{key}: {_value(value)}" for key, value in fields if _value(value)]
    entities = _entities(alert)
    if entities:
        lines.append("entities: " + "; ".join(entities))
    lines.append("related_event_count: " + str(len(alert.get("related_events") or [])))
    return "\n".join(lines)


def load_alerts(path: str | Path) -> Iterator[dict[str, Any]]:
    """Stream valid JSONL alerts and fail with a useful line number."""
    source = Path(path)
    with source.open(encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSON inválido en {source}:{line_number}: {exc}") from exc
            if not isinstance(alert, dict) or not alert.get("alert_id"):
                raise ValueError(f"Alerta inválida en {source}:{line_number}: falta alert_id")
            yield alert
