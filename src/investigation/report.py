"""Output format of the attack-chain reconstruction and its validation.

Why: the N2 report has an official schema (`docs/01_contexto/informe_incidente.schema.json`). The tool schema is
that file plus fields the analyst needs to read the chain (narrative, window, related alerts, per-step phase and
alert). Validation adds checks that only the database can answer: every cited event, alert and incident must exist,
so the model cannot invent evidence; the timeline must be chronological and include the escalated alert.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Protocol

from jsonschema import Draft202012Validator

SCHEMA_FILE = Path("01_contexto") / "informe_incidente.schema.json"
REPORT_TOOL = "emitir_informe"


class Lookup(Protocol):
    def existing(self, table: str, column: str, values: list[str]) -> set[str]: ...


def report_schema(data_dir: str | Path = "docs") -> dict[str, Any]:
    """Official N2 schema extended with the fields shown in the attack-chain view."""
    schema = json.loads((Path(data_dir) / SCHEMA_FILE).read_text(encoding="utf-8"))
    out = copy.deepcopy(schema)
    props = out["properties"]
    props["attack_summary"] = {
        "type": "string", "minLength": 40,
        "description": "Historia del ataque en 3-6 frases: origen, cómo avanzó, hasta dónde llegó y estado actual",
    }  # fmt: skip
    props["window"] = {
        "type": "object", "required": ["start", "end"],
        "properties": {"start": {"type": "string"}, "end": {"type": "string"}},
        "description": "Primer y último evento de la cadena (puede abarcar varios días)",
    }  # fmt: skip
    props["related_alerts"] = {
        "type": "array",
        "items": {"type": "object", "required": ["alert_id", "relation"],
                  "properties": {"alert_id": {"type": "string"}, "relation": {"type": "string"}}},
        "description": "Otras alertas que forman parte de la cadena y por qué",
    }  # fmt: skip
    item = props["timeline"]["items"]
    item["required"] = ["timestamp", "description"]
    item["properties"] |= {
        "phase": {"type": "string", "description": "Táctica MITRE (Initial Access, Execution, Lateral Movement...)"},
        "alert_id": {"type": "string", "description": "Alerta que detectó el paso, si alguna"},
        "source": {"type": "string", "description": "Fuente del log (edr, proxy, idp_signins...)"},
        "entity": {"type": "string", "description": "Usuario, equipo o IP protagonista del paso"},
    }
    props["timeline"]["minItems"] = 1
    props["confidence"] |= {"minimum": 0, "maximum": 1}
    out["required"] = [*schema["required"], "attack_summary", "window"]
    return out


def tool_schema(schema: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in schema.items() if k not in ("$schema", "title")}


def _schema_errors(report: Any, schema: dict[str, Any]) -> list[str]:
    errors = sorted(Draft202012Validator(schema).iter_errors(report), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '(raíz)'}: {e.message}" for e in errors]


def validate_report(report: Any, schema: dict[str, Any], alert_id: str, lookup: Lookup | None = None) -> list[str]:
    """All format, consistency and grounding errors (empty list = valid)."""
    errors = _schema_errors(report, schema)
    if not isinstance(report, dict):
        return errors
    if alert_id not in report.get("alert_ids", []):
        errors.append(f"alert_ids debe incluir la alerta escalada {alert_id}")
    timeline = [s for s in report.get("timeline", []) if isinstance(s, dict)]
    stamps = [str(s.get("timestamp", "")) for s in timeline]
    if stamps != sorted(stamps):
        errors.append("timeline: los pasos deben ir en orden cronológico (timestamp ascendente)")
    if lookup is None:
        return errors
    events = [str(s["event_id"]) for s in timeline if s.get("event_id")]
    missing = sorted(set(events) - lookup.existing("dim_log", "event_id", events))
    if missing:
        errors.append(f"timeline: event_id inexistentes en la base de datos: {', '.join(missing[:10])}")
    alerts = [*map(str, report.get("alert_ids", [])), *(str(s["alert_id"]) for s in timeline if s.get("alert_id")),
              *(str(r.get("alert_id")) for r in report.get("related_alerts", []) if isinstance(r, dict))]  # fmt: skip
    missing = sorted(set(alerts) - lookup.existing("alerts", "alert_id", alerts))
    if missing:
        errors.append(f"alert_id inexistentes en la base de datos: {', '.join(missing[:10])}")
    related = [str(x) for x in report.get("related_incidents", [])]
    known = lookup.existing("alert_incidents", "incident_id", related) | lookup.existing("alerts", "alert_id", related)
    missing = sorted(set(related) - known)
    if missing:
        errors.append(
            f"related_incidents: {', '.join(missing[:10])} no existen (usa incident_id de incident_links o alert_id)"
        )
    return errors
