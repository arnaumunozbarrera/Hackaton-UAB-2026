"""Alert discriminator: decide whether an alert needs the LLM.

Rule (agreed): an alert skips the LLM only when none of its cited logs is informative, at least one is explained
by authoritative context (N4) and the rest are in-alert duplicates (N1); the alert is neither high/critical (rule
or matrix) nor on OT. N4 already refuses to explain logs with free text, TI hits (G1) or a nearby unexplained
high/critical alert (G2), so those alerts always reach the LLM. The deterministic ticket cites every reference.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any

SEVERE = ("high", "critical")
# N4 categories that describe authorised activity (approved change, company rule, notified travel).
AUTHORISED = ("A_", "B_", "F_")


@dataclass
class Decision:
    route: str  # "llm" | "discriminator"
    reason: str
    ticket: dict[str, Any] | None = None
    references: list[str] = field(default_factory=list)


def decide(conn: sqlite3.Connection, alert_id: str, ctx: Any = None) -> Decision:
    states = conn.execute(
        "SELECT event_id, source, state, reason, reference FROM alert_log_selection WHERE alert_id = ? ORDER BY event_id",
        (alert_id,),
    ).fetchall()
    enriched = conn.execute(
        "SELECT rule_severity, matrix_base_severity, is_ot, technique_id, rule_id FROM alert_enriched WHERE alert_id = ?",
        (alert_id,),
    ).fetchone()
    if not states:
        return Decision("llm", "sin selección de logs: el LLM revisa la alerta completa")
    if enriched is None:
        return Decision("llm", "alerta sin enriquecer")
    rule_sev, base_sev, is_ot, technique, rule_id = enriched
    kinds = {s[2] for s in states}
    if kinds & {"kept", "unfiltered"}:
        return Decision("llm", "hay logs informativos")
    if "N4" not in kinds or not kinds <= {"N1", "N4"}:
        return Decision("llm", "los logs apartados no están explicados por contexto (N2/N3)")
    if rule_sev in SEVERE or base_sev in SEVERE:
        return Decision("llm", "severidad high/critical: siempre la revisa el LLM")
    if is_ot:
        return Decision("llm", "activo OT: solo escalado, lo revisa el LLM")
    explained = [s for s in states if s[2] == "N4"]
    categories = {(s[3] or "").split(":", 1)[-1] for s in explained}
    authorised = all(c.startswith(AUTHORISED) for c in categories)
    refs = sorted({s[4] for s in explained if s[4]})
    return Decision("discriminator", "todos los logs explicados por contexto", _ticket(conn, alert_id, ctx, explained,
                    authorised, refs, technique, rule_id), refs)  # fmt: skip


def _ticket(
    conn: sqlite3.Connection, alert_id: str, ctx: Any, explained: list[tuple], authorised: bool, refs: list[str],
    technique: str | None, rule_id: str,
) -> dict[str, Any]:  # fmt: skip
    rule_name = conn.execute("SELECT name FROM detection_rules WHERE rule_id = ?", (rule_id,)).fetchone()[0]
    verdict = "benign_true_positive" if authorised else "false_positive"
    affected: dict[str, list[str]] = {"users": [], "hosts": [], "business_services": [], "customers": []}
    if ctx is not None:
        affected = {
            "users": [u.user_key for u in ctx.users] + ctx.unknown_users,
            "hosts": [h.hostname for h in ctx.hosts] + ctx.unknown_hosts,
            "business_services": [s.name for s in ctx.services],
            "customers": list(ctx.entities.get("customers", [])),
        }
    joined = "; ".join(refs) or "contexto oficial"
    label = "actividad autorizada" if authorised else "actividad sin impacto según el contexto"
    return {
        "ticket_id": f"TKT-AUTO-{alert_id}",
        "alert_ids": [alert_id],
        "title": f"[Auto] {rule_name}: {label}",
        "verdict": verdict,
        "confidence": 0.85 if authorised else 0.75,
        "severity": "informational",
        "severity_rationale": (
            "Discriminador determinista: todos los logs citados están explicados por contexto oficial (N4) y la "
            "alerta no es high/critical ni OT; política: actividad autorizada = informational."
        ),
        "affected": affected,
        "summary": f"Cerrada sin LLM: {len(explained)} log(s) citados explicados por {joined}.",
        "evidence": [
            {
                "source": s[1] or "",
                "event_id": s[0],
                "finding": f"Explicado por {s[4] or 'contexto'} " f"({(s[3] or '').split(':', 1)[-1]})",
            }
            for s in explained
        ],  # fmt: skip
        "enrichment": [],
        "mitre": [technique] if technique else [],
        "recommended_actions": [
            {
                "action": "cerrar la alerta como " + verdict,
                "target": alert_id,
                "requires_approval": False,
                "justification": f"Referencias: {joined}",
            }
        ],  # fmt: skip
        "executed_actions": [],
        "escalation": {"escalate": False, "to": "", "reason": ""},
        "open_questions": [],
        "triage_seconds": 0,
    }
