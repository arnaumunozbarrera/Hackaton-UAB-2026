"""Alert discriminator: decide whether an alert needs the LLM.

Rule (agreed): an alert skips the LLM only when none of its cited logs is informative, at least one is explained
by authoritative context (N4) and the rest are in-alert duplicates (N1); the alert is neither high/critical (rule
or matrix) nor on OT. N4 already refuses to explain logs with free text, TI hits (G1) or a nearby unexplained
high/critical alert (G2), so those alerts always reach the LLM. The deterministic ticket cites every reference.

Grouping (politica_soc.md section 6): an alert that duplicates an alert already resolved as false_positive or
benign_true_positive (same rule, entities and day; resolved = closed by the discriminator or approved by an
operator) joins that ticket without the LLM, under the same severity and OT guards.
"""

from __future__ import annotations

import json
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
    if enriched is None:
        return Decision("llm", "alerta sin enriquecer")
    rule_sev, base_sev, is_ot, technique, rule_id = enriched
    if (
        rule_sev not in SEVERE
        and base_sev not in SEVERE
        and not is_ot
        and (parent := resolved_duplicate(conn, alert_id))
    ):
        return Decision("discriminator", f"duplicado de {parent[0]}, ya resuelta (agrupación, apartado 6)",
                        _grouped(alert_id, *parent), [parent[0]])  # fmt: skip
    if not states:
        return Decision("llm", "sin selección de logs: el LLM revisa la alerta completa")
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


def resolved_duplicate(conn: sqlite3.Connection, alert_id: str) -> tuple[str, dict[str, Any]] | None:
    """Earliest duplicate (same dedup key) already resolved as false/benign positive: (alert_id, ticket)."""
    try:
        row = conn.execute(
            "SELECT t.alert_id, t.ticket_json FROM alert_dedup d JOIN alert_dedup o ON o.dedup_hash = d.dedup_hash "
            "AND o.alert_id <> d.alert_id JOIN triage_tickets t ON t.alert_id = o.alert_id JOIN alerts a "
            "ON a.alert_id = o.alert_id WHERE d.alert_id = ? AND t.valid = 1 "
            "AND t.verdict IN ('false_positive', 'benign_true_positive') "
            "AND (t.route = 'discriminator' OR t.decision = 'approve') ORDER BY a.created_at LIMIT 1",
            (alert_id,),
        ).fetchone()
    except sqlite3.OperationalError:  # minimal schemas without the dedup table
        return None
    return (row[0], json.loads(row[1])) if row else None


def _grouped(alert_id: str, parent_id: str, parent: dict[str, Any]) -> dict[str, Any]:
    ids = list(dict.fromkeys([*(parent.get("alert_ids") or [parent_id]), alert_id]))
    return {
        **parent,
        "ticket_id": parent.get("ticket_id") or f"TKT-AUTO-{parent_id}",
        "alert_ids": ids,
        "title": f"[Auto] Duplicado de {parent_id}: {parent.get('title', '')}".strip(),
        "summary": f"Misma regla, entidades y día que {parent_id}, ya resuelta como {parent.get('verdict')}. "
        f"Se agrupa en su ticket sin LLM. {parent.get('summary', '')}".strip(),
        "recommended_actions": [
            {
                "action": f"agrupar en el ticket de {parent_id}",
                "target": alert_id,
                "requires_approval": False,
                "justification": "politica_soc.md, apartado 6",
            }
        ],  # fmt: skip
        "executed_actions": [],
        "escalation": {"escalate": False, "to": "", "reason": ""},
        "open_questions": [],
    }
