"""Deterministic SOC policy automation, applied to every ticket after triage and before it is stored (no LLM).

Why: what politica_soc.md fixes as a rule needs no model judgement, so it is applied by code, the same way for
discriminator and LLM tickets, and it never costs a repair round with the model:
1. Severity is not touched here: it is server-owned (src.severity, matrix rule severity x criticality) and is
   frozen in severity_assessments before this step, so the ticket and its assessment always match.
2. Approvals (section 4): containment actions that need N2 get requires_approval = true.
3. Mandatory escalation (sections 3 and 5): true_positive high/critical/medium, execution, credential theft,
   persistence, personal data (DPO), fraud, attack chains and OT (Operations).
4. SLA (section 3): triage deadline from the moment the SOC received the alert, escalation path and notifications
   (recorded in a simulated outbox: there is no mail or phone channel).
5. N1 containment (section 4, "Sí, ejecutar"): block_ioc for malicious indicators and purge_email for phishing,
   executed against the SOC API without approval for true_positive tickets (TARVIA_AUTO_CONTAINMENT=0 disables it).
   Actions that need approval run only after the operator approves the ticket (`approved_actions`).
Every change is recorded in ticket_automation so the operator sees what the policy did and why.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..prompt_builder.policy import Policy, load_policy

SEVERE = ("high", "critical")
APPROVAL_KEYWORDS = (
    "aislar", "isolate", "deshabilitar", "disable", "revocar", "revoke", "reset", "restablecer", "contraseña",
    "password", "desactivar", "clave", "access_key",
)  # fmt: skip
ESCALATION_TACTICS = {
    "Execution": "ejecución",
    "Credential Access": "robo de credenciales",
    "Persistence": "persistencia",
}
PERSONAL_DATA_RULES = ("UC-DLP-001", "UC-DLP-002", "UC-AI-002", "UC-CLD-003", "UC-CLD-004")
FRAUD_RULES = ("UC-EML-004", "UC-WEB-003", "UC-EDR-012")
# Dual-use services: never blocked globally without N2 (politica_soc.md section 4).
DUAL_USE = ("mega.nz", "mega.io", "anydesk", "teamviewer", "dropbox", "wetransfer", "drive.google", "onedrive",
            "github", "googleapis", "microsoft", "office", "amazonaws", "linkedin")  # fmt: skip
OWN_DOMAINS = ("tarvia",)
# Operator-approved recommended action -> SOC API containment action (first match wins: most specific first).
ACTION_MAP = (
    (("clave", "access_key", "access key"), "disable_access_key"),
    (("aislar", "isolate"), "isolate_host"),
    (("revocar", "revoke"), "revoke_sessions"),
    (("contraseña", "password", "reset", "restablecer"), "reset_password"),
    (("deshabilitar", "disable", "desactivar"), "disable_user"),
    (("purgar", "purge"), "purge_email"),
    (("bloquear", "block"), "block_ioc"),
)
NO_APPROVAL = ("block_ioc", "purge_email")
OT_MARKERS = ("plc-", "hmi-", "logistics-ot")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# ------------------------------------------------------------------------------------------------ SLA table
@dataclass(frozen=True)
class SlaRule:
    severity: str
    minutes: int
    label: str
    escalation: str
    notify: tuple[str, ...]


def _minutes(text: str) -> int:
    if m := re.search(r"(\d+)\s*min", text):
        return int(m.group(1))
    if m := re.search(r"(\d+)\s*h", text):
        return int(m.group(1)) * 60
    return 24 * 60  # "Revisión en lote diaria"


def parse_sla(policy: Policy) -> dict[str, SlaRule]:
    """Section 3 of politica_soc.md: severity -> time to triage, escalation and notification."""
    rows = [r for r in policy.sections.get("3", "").splitlines() if r.startswith("|") and "---" not in r]
    out = {}
    for row in rows[1:]:
        sev, time_txt, esc, notif = ([c.strip() for c in row.strip("|").split("|")] + ["", "", "", ""])[:4]
        notify = tuple(p.strip() for p in re.split(r"\s+y\s+|,", notif) if p.strip() and p.strip() not in "—-")
        out[sev] = SlaRule(sev, _minutes(time_txt), time_txt, esc, notify)
    return out


# ------------------------------------------------------------------------------------------------ alert facts
@dataclass
class Facts:
    """What the deterministic rules need about an alert, read from the derived database layer."""

    rule_id: str = ""
    tactic: str = ""
    source_product: str = ""
    rule_severity: str = ""
    base_severity: str = ""
    is_ot: bool = False
    received_at: str = ""
    message_id: str = ""
    indicators: list[dict[str, Any]] = field(default_factory=list)
    chain: list[str] = field(default_factory=list)  # other true_positive alerts in the same non-authorised incident


def _one(conn: sqlite3.Connection, sql: str, params: tuple) -> tuple | None:
    try:
        return conn.execute(sql, params).fetchone()
    except sqlite3.OperationalError:  # minimal schemas (tests, partial databases)
        return None


def _all(conn: sqlite3.Connection, sql: str, params: tuple) -> list[tuple]:
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []


def mark_received(conn: sqlite3.Connection) -> int:
    """Start the SLA clock of every alert not seen before: the moment the SOC platform received it."""
    cur = conn.execute(
        "INSERT OR IGNORE INTO alert_received (alert_id, received_at) SELECT alert_id, ? FROM alerts", (now(),)
    )
    conn.commit()
    return cur.rowcount


def facts(conn: sqlite3.Connection, alert_id: str) -> Facts:
    f = Facts()
    row = _one(conn, "SELECT a.rule_id, r.tactic, r.source_product, a.severity FROM alerts a JOIN detection_rules r "
               "ON r.rule_id = a.rule_id WHERE a.alert_id = ?", (alert_id,))  # fmt: skip
    if row:
        f.rule_id, f.tactic, f.source_product, f.rule_severity = (str(v or "") for v in row)
    row = _one(conn, "SELECT matrix_base_severity, is_ot FROM alert_enriched WHERE alert_id = ?", (alert_id,))
    if row:
        f.base_severity, f.is_ot = str(row[0] or ""), bool(row[1])
    row = _one(conn, "SELECT received_at FROM alert_received WHERE alert_id = ?", (alert_id,))
    f.received_at = row[0] if row else now()
    row = _one(conn, "SELECT json_extract(evidence_json, '$.message_id') FROM alerts WHERE alert_id = ?", (alert_id,))
    f.message_id = str(row[0]) if row and row[0] else ""
    f.indicators = [
        {"type": t, "value": v, "reputation": rep, "sandbox": sbx}
        for t, v, rep, sbx in _all(
            conn,
            "SELECT b.entity_type, b.entity_value, c.reputation, c.sandbox_verdict FROM bridge_alert_entity b "
            "LEFT JOIN dim_context c ON c.context_key = b.context_key WHERE b.alert_id = ? "
            "AND b.entity_type IN ('ip', 'domain', 'url', 'file')",
            (alert_id,),
        )
    ]
    f.chain = [
        r[0]
        for r in _all(
            conn,
            "SELECT DISTINCT o.alert_id FROM alert_incidents i JOIN alert_incidents o ON o.incident_id = i.incident_id "
            "AND o.alert_id <> i.alert_id JOIN triage_tickets t ON t.alert_id = o.alert_id WHERE i.alert_id = ? "
            "AND i.is_authorised = 0 AND t.verdict = 'true_positive'",
            (alert_id,),
        )
    ]
    return f


# ------------------------------------------------------------------------------------------------ rules
def approvals(ticket: dict[str, Any]) -> list[dict[str, str]]:
    changes = []
    for action in ticket.get("recommended_actions") or []:
        if not isinstance(action, dict):
            continue
        text = f" {action.get('action', '')} {action.get('target', '')} ".lower()
        if any(k in text for k in APPROVAL_KEYWORDS) and not action.get("requires_approval"):
            action["requires_approval"] = True
            changes.append(
                {"rule": "approval", "detail": f"'{action.get('action')}' requiere aprobación de N2 (apartado 4)"}
            )
    return changes


def escalation(ticket: dict[str, Any], f: Facts, sla: dict[str, SlaRule]) -> tuple[list[str], list[str], list[str]]:
    """(reasons, destinations, extra recipients) required by the policy for this ticket."""
    verdict, sev = ticket.get("verdict"), ticket.get("severity")
    reasons, to, extra = [], [], []
    if verdict == "true_positive":
        if sev in SEVERE:
            reasons.append(f"true_positive {sev} (apartado 5)")
        elif sev == "medium":
            reasons.append("true_positive medium: indicios de compromiso tras el triaje (apartado 3)")
        if f.tactic in ESCALATION_TACTICS:
            reasons.append(f"{ESCALATION_TACTICS[f.tactic]} confirmada (apartado 5)")
        if f.rule_id in PERSONAL_DATA_RULES:
            reasons.append("datos personales que han podido salir de la organización: implica DPO (apartado 5)")
            extra.append("DPO")
        if f.rule_id in FRAUD_RULES:
            reasons.append("fraude económico (apartado 5)")
        if f.chain:
            reasons.append(f"cadena de ataque con {', '.join(f.chain[:5])} (apartado 5)")
        if reasons:
            rule = sla.get(sev or "")
            to.append(f"N2 · {rule.escalation}" if rule and sev in SEVERE else "N2")
    if f.is_ot and verdict not in ("false_positive", "benign_true_positive"):
        reasons.append("activo OT: el SOC solo escala (apartado 4)")
        to.append("Responsable de Operaciones")
        extra.append("Responsable de Operaciones")
    return reasons, to, extra


def apply_escalation(ticket: dict[str, Any], reasons: list[str], to: list[str]) -> list[dict[str, str]]:
    if not reasons:
        return []
    esc = ticket.setdefault("escalation", {})
    if not isinstance(esc, dict):
        esc = ticket["escalation"] = {}
    changed = not esc.get("escalate")
    esc["escalate"] = True
    if not str(esc.get("to") or "").strip():
        esc["to"], changed = " + ".join(to), True
    if not str(esc.get("reason") or "").strip():
        esc["reason"], changed = "; ".join(reasons), True
    return [{"rule": "escalation", "detail": f"Escalado a {esc['to']}: {'; '.join(reasons)}"}] if changed else []


def _blockable(ind: dict[str, Any]) -> bool:
    value = str(ind.get("value") or "").lower()
    if not value or "malicious" not in (ind.get("reputation") or "", ind.get("sandbox") or ""):
        return False
    if any(d in value for d in DUAL_USE + OWN_DOMAINS):
        return False
    try:
        return not ipaddress.ip_address(value).is_private
    except ValueError:
        return True


def containment_plan(ticket: dict[str, Any], f: Facts) -> list[dict[str, str]]:
    """N1 actions the policy lets the SOC execute without approval (section 4)."""
    if ticket.get("verdict") != "true_positive":
        return []
    plan = [{"action": "block_ioc", "target": str(i["value"]), "reason": f"indicador {i['type']} malicioso en TI/sandbox"}
            for i in f.indicators if _blockable(i)]  # fmt: skip
    if f.source_product == "EMAIL_GW" and f.message_id:
        plan.append({"action": "purge_email", "target": f.message_id, "reason": "correo de phishing confirmado"})
    seen, out = set(), []
    for p in plan:
        if (p["action"], p["target"]) not in seen:
            seen.add((p["action"], p["target"]))
            out.append(p)
    return out


def notifications(ticket: dict[str, Any], sla: dict[str, SlaRule], extra: list[str]) -> list[dict[str, str]]:
    sev, verdict = ticket.get("severity"), ticket.get("verdict")
    out = []
    if verdict in ("true_positive", "needs_more_info") and sev in sla:
        rule = sla[sev]
        if sev == "critical" and (ticket.get("escalation") or {}).get("escalate"):
            out.append({"recipient": "N2 de guardia", "channel": "teléfono (simulado)", "reason": rule.escalation})
        out += [
            {"recipient": r, "channel": "correo (simulado)", "reason": f"SLA {sev}: {rule.label}"} for r in rule.notify
        ]
    out += [{"recipient": r, "channel": "correo (simulado)", "reason": "escalado obligatorio"} for r in extra]
    seen, uniq = set(), []
    for n in out:
        if n["recipient"] not in seen:
            seen.add(n["recipient"])
            uniq.append(n)
    return uniq


# ------------------------------------------------------------------------------------------------ engine
class PolicyAutomation:
    def __init__(self, data_dir: str | Path = "docs", auto_containment: bool | None = None) -> None:
        self.policy = load_policy(Path(data_dir) / "01_contexto" / "politica_soc.md")
        self.sla = parse_sla(self.policy)
        env = os.environ.get("TARVIA_AUTO_CONTAINMENT", "1").strip().lower() not in ("0", "false", "no", "off")
        self.auto_containment = env if auto_containment is None else auto_containment

    def apply(self, conn: sqlite3.Connection, alert_id: str, ticket: dict[str, Any] | None) -> dict[str, Any]:
        """Apply the deterministic rules to the ticket (in place) and return the automation record."""
        f = facts(conn, alert_id)
        changes: list[dict[str, str]] = []
        reasons: list[str] = []
        extra: list[str] = []
        plan: list[dict[str, str]] = []
        notify: list[dict[str, str]] = []
        sev_before = ticket.get("severity") if isinstance(ticket, dict) else None
        if isinstance(ticket, dict):
            changes += approvals(ticket)
            reasons, to, extra = escalation(ticket, f, self.sla)
            changes += apply_escalation(ticket, reasons, to)
            plan = containment_plan(ticket, f) if self.auto_containment else []
            notify = notifications(ticket, self.sla, extra)
        sev = (ticket or {}).get("severity") if isinstance(ticket, dict) else None
        sev = sev if sev in self.sla else (f.base_severity if f.base_severity in self.sla else "low")
        rule = self.sla[sev] if sev in self.sla else SlaRule(sev, 1440, "24 h", "No", ())
        due = _parse_ts(f.received_at) + timedelta(minutes=rule.minutes)
        esc = (ticket or {}).get("escalation") or {} if isinstance(ticket, dict) else {}
        return {
            "alert_id": alert_id, "base_severity": f.base_severity, "severity_before": sev_before, "severity": sev,
            "sla_minutes": rule.minutes, "sla_label": rule.label, "received_at": f.received_at,
            "sla_due_at": due.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "escalation_path": rule.escalation, "escalation_to": esc.get("to") if esc.get("escalate") else "",
            "escalation_reasons": reasons, "notify": notify, "changes": changes, "plan": plan,
        }  # fmt: skip

    @staticmethod
    def save(conn: sqlite3.Connection, record: dict[str, Any]) -> None:
        conn.execute(
            "INSERT OR REPLACE INTO ticket_automation (alert_id, base_severity, severity_before, severity, sla_minutes, "
            "sla_label, received_at, sla_due_at, escalation_path, escalation_to, reasons_json, changes_json, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (record["alert_id"], record["base_severity"], record["severity_before"], record["severity"],
             record["sla_minutes"], record["sla_label"], record["received_at"], record["sla_due_at"],
             record["escalation_path"], record["escalation_to"], json.dumps(record["escalation_reasons"], ensure_ascii=False),
             json.dumps(record["changes"], ensure_ascii=False), now()),
        )  # fmt: skip
        for n in record["notify"]:
            conn.execute(
                "INSERT OR IGNORE INTO soc_notifications (alert_id, recipient, channel, reason, status, created_at) "
                "VALUES (?, ?, ?, ?, 'queued', ?)",
                (record["alert_id"], n["recipient"], n["channel"], n["reason"], now()),
            )
        conn.commit()


# ------------------------------------------------------------------------------------------------ execution
def already_done(conn: sqlite3.Connection, alert_id: str, action: str, target: str) -> bool:
    return _one(conn, "SELECT 1 FROM soc_actions WHERE alert_id = ? AND action = ? AND target = ? AND status = 'ok'",
                (alert_id, action, target)) is not None  # fmt: skip


def record_action(conn: sqlite3.Connection, alert_id: str, action: dict[str, Any], mode: str, status: str,
                  detail: str = "", token: str = "") -> dict[str, Any]:  # fmt: skip
    row = {"alert_id": alert_id, "action": action["action"], "target": action["target"], "mode": mode,
           "status": status, "detail": detail[:500], "approval_token": token, "reason": action.get("reason", ""),
           "created_at": now()}  # fmt: skip
    conn.execute(
        "INSERT INTO soc_actions (alert_id, action, target, mode, status, reason, detail, approval_token, created_at) "
        "VALUES (:alert_id, :action, :target, :mode, :status, :reason, :detail, :approval_token, :created_at)",
        row,
    )
    conn.commit()
    return row


def execute(api: Any, action: dict[str, Any], ticket_id: str, approver: str = "") -> tuple[str, str, str]:
    """Run one containment action on the SOC API. Returns (status, detail, approval_token)."""
    token = ""
    try:
        if action["action"] not in NO_APPROVAL:
            token = api.post("/approvals", {"action": action["action"], "target": action["target"],
                                            "approver": approver or "operador", "reason": action.get("reason", "")})[
                "approval_token"]  # fmt: skip
        res = api.post(f"/containment/{action['action']}", {"target": action["target"], "ticket_id": ticket_id,
                       "justification": action.get("reason") or "política SOC", "approval_token": token})  # fmt: skip
        return "ok", str(res.get("result", "ok")), token
    except Exception as exc:  # API down or policy refusal (403): recorded, never raised
        return "failed", f"{type(exc).__name__}: {exc}", token


BREACH_RECIPIENT = "Responsable SOC · SLA incumplido"


def sla_breaches(conn: sqlite3.Connection, at: str | None = None) -> list[str]:
    """Pending tickets past their triage deadline: notify the SOC lead once per alert (simulated outbox).

    Operating rule (section 3 sets the deadlines, not what happens when one is missed): the breach goes to the
    SOC lead so the queue is re-prioritised. Informational tickets (daily batch review) are excluded.
    """
    at = at or now()
    rows = _all(
        conn,
        "SELECT ta.alert_id, ta.severity, ta.sla_label, ta.sla_due_at FROM ticket_automation ta "
        "JOIN triage_tickets t ON t.alert_id = ta.alert_id WHERE t.decision IS NULL AND t.route = 'llm' "
        "AND ta.severity <> 'informational' AND ta.sla_due_at < ? AND NOT EXISTS (SELECT 1 FROM soc_notifications n "
        "WHERE n.alert_id = ta.alert_id AND n.recipient = ?)",
        (at, BREACH_RECIPIENT),
    )
    for alert_id, sev, label, due in rows:
        conn.execute(
            "INSERT OR IGNORE INTO soc_notifications (alert_id, recipient, channel, reason, status, created_at) "
            "VALUES (?, ?, 'correo (simulado)', ?, 'queued', ?)",
            (alert_id, BREACH_RECIPIENT, f"SLA {sev} ({label}) incumplido: vencía {due}", at),
        )
    if rows:
        conn.commit()
    return [r[0] for r in rows]


def approved_plan(ticket: dict[str, Any]) -> list[dict[str, str]]:
    """Recommended actions mapped to SOC API actions, to run once the operator approves the ticket."""
    out = []
    for a in ticket.get("recommended_actions") or []:
        if not isinstance(a, dict):
            continue
        text = f"{a.get('action', '')}".lower()
        target = str(a.get("target") or "").strip()
        api_action = next((name for keys, name in ACTION_MAP if any(k in text for k in keys)), None)
        if any(m in f"{text} {target}".lower() for m in OT_MARKERS):
            api_action = "ot"
        out.append({"action": api_action or "manual", "target": target, "reason": a.get("justification") or a.get("action", ""),
                    "label": a.get("action", "")})  # fmt: skip
    return out
