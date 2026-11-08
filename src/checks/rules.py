"""Deterministic basic checks for one stored alert: close it automatically or keep it for the LLM.

An alert is closed only when every cited event is explained by authoritative context (N4 categories A-F in
`src.log_noise_discard.explained`) and no guard applies. Guards (politica_soc.md and the N4 safety rules):

- rule (or alert) severity high/critical: never closed automatically;
- OT: an asset in LOGISTICS-OT, a UC-OT-* rule or a firewall event towards the OT zone;
- G1: an indicator with malicious/suspicious TIP reputation in the alert entities, evidence or events;
- G2: another high/critical alert of the same entity (user, host, IP/IOC, customer) within +-24 h that is not
  explained (not closed by these checks nor by an analyst as benign/false positive);
- no events in the database, or a cited event missing;
- open text: an explained event with an attacker-writable free-text field keeps the alert.

The free text of an alert or event never closes anything by itself: it is only data for the matchers.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Any

from ..log_noise_discard.config import NoiseFilterConfig
from ..log_noise_discard.context import Context, parse_ts
from ..log_noise_discard.explained import (
    OT_ZONE,
    Explanation,
    _has_bad_indicator,
    _travel_explained,
    explain_log,
    has_open_text,
)
from ..log_noise_discard.stages import LogRecord
from .db_context import DbFacts, Facts, alert_context, load_context
from .db_events import alert_records

SEVERE = ("high", "critical")
BENIGN_CATEGORIES = ("A_cambio_aprobado", "B_regla_empresa", "F_viaje_dispositivo")
EXPLAINED_VERDICTS = ("false_positive", "benign_true_positive")


@dataclass
class CheckResult:
    """Outcome of the basic checks for one alert (stored in triage_checks)."""

    alert_id: str
    rule_id: str
    discard: bool
    verdict: str | None = None  # benign_true_positive | false_positive when discarded
    severity: str | None = None
    reasons: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    guards: list[str] = field(default_factory=list)
    explanations: dict[str, Explanation] = field(default_factory=dict)  # event_id -> context that explains it
    open_text: list[str] = field(default_factory=list)  # explained events kept for their free text
    unexplained: list[str] = field(default_factory=list)
    sources: dict[str, str] = field(default_factory=dict)  # event_id -> log source

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["explanations"] = {k: asdict(v) for k, v in self.explanations.items()}
        return data


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    cur = conn.execute(sql, params)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _entity_values(conn: sqlite3.Connection, alert_id: str) -> list[str]:
    sql = (
        "SELECT value FROM alert_indicators WHERE alert_id = ?1 UNION ALL SELECT sha256 FROM alert_files "
        "WHERE alert_id = ?1 AND sha256 IS NOT NULL UNION ALL SELECT file_name FROM alert_files WHERE alert_id = ?1 "
        "UNION ALL SELECT customer_id FROM alert_customers WHERE alert_id = ?1"
    )
    return [r[0] for r in conn.execute(sql, {"1": alert_id}) if r[0]]


def _chained_alerts(conn: sqlite3.Connection, alert: dict[str, Any]) -> list[str]:
    """Other unexplained high/critical alerts sharing an entity within +-24 h (guard G2)."""
    created = parse_ts(alert["created_at"])
    window = [(created + timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%S.000Z") for h in (-24, 24)]
    sql = (
        "SELECT o.alert_id FROM alerts o JOIN detection_rules r ON r.rule_id = o.rule_id "
        "WHERE o.alert_id <> ?1 AND o.created_at BETWEEN ?2 AND ?3 "
        "AND (r.base_severity IN ('high', 'critical') OR o.severity IN ('high', 'critical')) "
        "AND NOT EXISTS (SELECT 1 FROM triage_checks c JOIN triage_runs t ON t.run_id = c.run_id "
        "  WHERE t.alert_id = o.alert_id AND c.discard = 1) "
        "AND NOT EXISTS (SELECT 1 FROM alert_history h WHERE h.alert_id = o.alert_id "
        "  AND h.verdict IN ('false_positive', 'benign_true_positive')) "
        "AND (EXISTS (SELECT 1 FROM alert_users a JOIN alert_users b ON b.user_id = a.user_id "
        "  WHERE a.alert_id = ?1 AND b.alert_id = o.alert_id) "
        "OR EXISTS (SELECT 1 FROM alert_assets a JOIN alert_assets b ON b.asset_id = a.asset_id "
        "  WHERE a.alert_id = ?1 AND b.alert_id = o.alert_id) "
        "OR EXISTS (SELECT 1 FROM alert_indicators a JOIN alert_indicators b ON b.value = a.value "
        "  WHERE a.alert_id = ?1 AND b.alert_id = o.alert_id) "
        "OR EXISTS (SELECT 1 FROM alert_customers a JOIN alert_customers b ON b.customer_id = a.customer_id "
        "  WHERE a.alert_id = ?1 AND b.alert_id = o.alert_id)) ORDER BY o.created_at"
    )
    return [r[0] for r in conn.execute(sql, {"1": alert["alert_id"], "2": window[0], "3": window[1]})]


def _guards(
    conn: sqlite3.Connection, alert: dict[str, Any], records: list[tuple[str, dict[str, Any]]], ctx: Context
) -> list[str]:
    aid, rule = alert["alert_id"], alert["rule_id"]
    guards = []
    if alert["base_severity"] in SEVERE or alert["severity"] in SEVERE:
        guards.append(
            f"Severidad {alert['base_severity']} (regla) / {alert['severity']} (alerta): nunca se cierra "
            "automáticamente (política, apartado 5)"
        )
    ot_assets = [
        r["hostname"]
        for r in _rows(
            conn,
            "SELECT s.hostname FROM alert_assets a JOIN assets s ON s.asset_id = a.asset_id "
            "WHERE a.alert_id = ? AND s.zone_id = ?",
            (aid, OT_ZONE),
        )
    ]
    ot_events = [e["event_id"] for s, e in records if s == "firewall" and e.get("zone_dst") == OT_ZONE]
    if rule.startswith("UC-OT-") or ot_assets or ot_events:
        detail = ", ".join(ot_assets + ot_events) or rule
        guards.append(f"OT ({detail}): solo se escala al responsable de Operaciones, nunca se cierra solo")
    bad = ctx.bad_indicators
    evidence = json.loads(alert["evidence_json"] or "{}")
    tip_hits = sorted({v for v in [*_entity_values(conn, aid), *_strings(evidence)] if v.lower() in bad})
    tip_events = [e["event_id"] for _, e in records if _has_bad_indicator(e, bad)]
    if tip_hits or tip_events:
        guards.append(f"G1: indicador malicioso/sospechoso en el TIP ({', '.join(tip_hits + tip_events)[:300]})")
    chained = _chained_alerts(conn, alert)
    if chained:
        guards.append(f"G2: otra alerta high/critical sin explicar de la misma entidad en ±24 h ({', '.join(chained)})")
    return guards


def run_checks(
    conn: sqlite3.Connection,
    alert_id: str,
    *,
    base: Context | None = None,
    facts: Facts | None = None,
    cfg: NoiseFilterConfig | None = None,
) -> CheckResult:
    """Run the basic checks on a stored alert. `base` can be cached across alerts (see `load_context`)."""
    rows = _rows(
        conn,
        "SELECT a.alert_id, a.rule_id, a.severity, a.created_at, a.evidence_json, r.base_severity "
        "FROM alerts a JOIN detection_rules r ON r.rule_id = a.rule_id WHERE a.alert_id = ?",
        (alert_id,),
    )
    if not rows:
        raise KeyError(f"Alert {alert_id} is not in the database")
    alert = rows[0]
    cfg = cfg or NoiseFilterConfig()
    records = alert_records(conn, alert_id)
    cited = conn.execute("SELECT COUNT(*) FROM alert_events WHERE alert_id = ?", (alert_id,)).fetchone()[0]
    ctx = alert_context(base or load_context(conn), facts or DbFacts(conn), records)
    result = CheckResult(alert_id, alert["rule_id"], discard=False, sources={e["event_id"]: s for s, e in records})

    logs = {e["event_id"]: LogRecord(e["event_id"], s, (), "", 0, e) for s, e in records}
    for eid, rec in logs.items():
        exp = explain_log(rec, ctx)
        if exp:
            result.explanations[eid] = exp
    if alert["rule_id"] == "UC-IDP-001":
        travel = _travel_explained([r for r in logs.values() if r.source == "idp_signins"], ctx)
        if travel:
            for eid in logs:
                result.explanations.setdefault(eid, travel)
    result.unexplained = [eid for eid in logs if eid not in result.explanations]
    result.open_text = [eid for eid in result.explanations if has_open_text(logs[eid], cfg)]
    result.references = sorted({exp.reference for exp in result.explanations.values()})
    result.reasons = [
        f"{eid} ({logs[eid].source}): {exp.reference} [{exp.category}]" for eid, exp in result.explanations.items()
    ]

    result.guards = _guards(conn, alert, records, ctx)
    if not records:
        result.guards.append("Sin eventos de log en la base: no hay nada que explicar")
    elif len(records) < cited:
        result.guards.append(f"Faltan {cited - len(records)} eventos citados en la base")
    if result.unexplained:
        result.reasons.append(f"Eventos sin explicación de contexto: {', '.join(result.unexplained)}")
    if result.open_text:
        result.reasons.append(
            f"Explicados pero con texto libre (lo puede escribir un atacante): {', '.join(result.open_text)}"
        )

    if not result.guards and not result.unexplained and not result.open_text and records:
        categories = {exp.category for exp in result.explanations.values()}
        result.discard = True
        result.verdict = "benign_true_positive" if categories & set(BENIGN_CATEGORIES) else "false_positive"
        result.severity = "informational" if "A_cambio_aprobado" in categories else "low"
    return result
