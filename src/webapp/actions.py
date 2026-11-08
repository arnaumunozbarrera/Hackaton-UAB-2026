"""Write side of the web UI: analyst decisions on a ticket and the containment they trigger.

Rules (politica_soc.md and the brief):

- every decision is stored in `analyst_decisions` with the analyst's name; the model never decides;
- `alert_history` (the human verdict) is written only when the analyst *accepts* the verdict; accepting with an
  `override_verdict` records the analyst's verdict instead of the model's; `needs_more_info` needs an override;
- an accepted action runs against the SOC API only if it maps to a supported containment action. `block_ioc` and
  `purge_email` run directly; the others first register the analyst's approval (`POST /approvals`) and pass its
  token. Anything that targets OT (LOGISTICS-OT assets, PLC/HMI, the OT zone) is refused and must be escalated;
- an action already executed successfully for the same ticket item is not executed again;
- text written by the model (action, target, justification) is only data: it selects nothing outside the
  supported actions and never authorises anything by itself.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from ..llm_triage.validator import OT_MARKERS
from ..workflow.store import dumps, now

FINAL_VERDICTS = ("true_positive", "false_positive", "benign_true_positive")
NO_APPROVAL = ("block_ioc", "purge_email")
# Ordered: the first matching pattern wins (reset before disable: "deshabilitar y resetear" -> reset_password).
ACTION_PATTERNS = (
    ("disable_access_key", r"access[_ ]?key|clave de acceso|disable_access_key"),
    ("reset_password", r"reset|restablec|contraseñ|password"),
    ("revoke_sessions", r"revoc|revoke|sesion|session"),
    ("disable_user", r"deshabilit|disable|desactiv|bloquear (la )?cuenta|suspend"),
    ("isolate_host", r"aisla|isolat|contener equipo|contain host"),
    ("purge_email", r"purg|eliminar (el )?correo|retirar (el )?correo"),
    ("block_ioc", r"bloque|block|ioc"),
)


class DecisionError(ValueError):
    """Invalid decision request (shown to the analyst as a 400/409)."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


@dataclass
class Decision:
    item: str  # "verdict" | "action:<n>"
    decision: str  # accepted | rejected
    analyst: str
    run_id: int | None = None
    override_verdict: str | None = None
    comment: str = ""


def api_action(action: dict[str, Any]) -> str | None:
    """Supported SOC API containment action for a recommended action, or None (escalate, review...)."""
    text = f"{action.get('action', '')}".lower()
    if re.search(r"escal|revis|review|monitor|vigil|notific|avis", text):
        return None
    return next((name for name, pattern in ACTION_PATTERNS if re.search(pattern, text)), None)


def ot_reason(conn: sqlite3.Connection, target: str) -> str | None:
    """Why a target is OT (and must not be touched), or None."""
    text = f" {target} ".lower()
    if any(m in text for m in OT_MARKERS):
        return "el objetivo menciona OT"
    names = [t.strip() for t in re.split(r"[,;\s]+", target) if t.strip()]
    for name in names:
        row = conn.execute(
            "SELECT hostname FROM assets WHERE (hostname = ? COLLATE NOCASE OR ip = ?) AND zone_id = 'LOGISTICS-OT'",
            (name, name),
        ).fetchone()
        if row:
            return f"{row[0]} está en LOGISTICS-OT"
    return None


def _ticket(conn: sqlite3.Connection, alert_id: str, run_id: int | None) -> tuple[int, dict[str, Any]]:
    if run_id is None:
        row = conn.execute(
            "SELECT run_id, ticket_json FROM triage_tickets WHERE alert_id = ? ORDER BY run_id DESC LIMIT 1",
            (alert_id,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT run_id, ticket_json FROM triage_tickets WHERE alert_id = ? AND run_id = ?", (alert_id, run_id)
        ).fetchone()
    if row is None:
        raise DecisionError("La alerta no tiene ticket (o el run_id no es de esta alerta)", 404)
    return int(row[0]), json.loads(row[1])


def _record(conn: sqlite3.Connection, alert_id: str, run_id: int, d: Decision) -> int:
    cur = conn.execute(
        "INSERT INTO analyst_decisions (alert_id, run_id, item, decision, override_verdict, analyst, comment, "
        "decided_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (alert_id, run_id, d.item, d.decision, d.override_verdict, d.analyst, d.comment or None, now()),
    )
    return int(cur.lastrowid)


def _execute(
    conn: sqlite3.Connection, api: Any, alert_id: str, run_id: int, index: int, action: dict[str, Any], d: Decision,
    ticket_id: str,
) -> dict[str, Any]:  # fmt: skip
    name, target = api_action(action), str(action.get("target") or "")
    if name is None:
        return {"executed": False, "reason": "Acción sin ejecución en la API (escalado, revisión...): queda registrada"}
    done = conn.execute(
        "SELECT 1 FROM executed_actions WHERE run_id = ? AND action_index = ? AND status = 'ok'", (run_id, index)
    ).fetchone()
    if done:
        raise DecisionError("Esta acción ya se ejecutó para este ticket", 409)
    ot = ot_reason(conn, target)
    token, status, result = None, "ok", None
    if ot:
        status, result = "refused", {"detail": f"Política: el SOC no actúa sobre OT ({ot}); escalar a Operaciones"}
    elif api is None:
        status, result = "error", {"detail": "API del SOC no configurada"}
    else:
        justification = (d.comment or action.get("justification") or f"Aprobado por {d.analyst}")[:500]
        try:
            if name not in NO_APPROVAL:
                approval = api.approve(name, target, d.analyst, justification)
                token = approval["approval_token"]
            result = api.contain(name, target, justification, approval_token=token or "", ticket_id=ticket_id)
        except PermissionError as exc:
            status, result = "refused", {"detail": str(exc)}
        except Exception as exc:  # SocApiError, network...: stored, shown to the analyst
            refused = getattr(exc, "status", None) == 403
            status, result = ("refused" if refused else "error"), {"detail": getattr(exc, "detail", str(exc))}
    conn.execute(
        "INSERT INTO executed_actions (alert_id, run_id, action_index, action, target, approval_token, status, "
        "api_result_json, executed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (alert_id, run_id, index, name, target, token, status, dumps(result), now()),
    )
    return {"executed": status == "ok", "action": name, "target": target, "status": status, "result": result}


def decide(conn: sqlite3.Connection, api: Any, alert_id: str, d: Decision) -> dict[str, Any]:
    """Store one analyst decision and apply its effects (alert_history, containment). Commits or rolls back."""
    if not d.analyst.strip():
        raise DecisionError("Indica el nombre del analista")
    if d.decision not in ("accepted", "rejected"):
        raise DecisionError("decision debe ser accepted o rejected")
    if d.override_verdict is not None and d.override_verdict not in FINAL_VERDICTS:
        raise DecisionError(f"override_verdict debe ser uno de {FINAL_VERDICTS}")
    run_id, ticket = _ticket(conn, alert_id, d.run_id)
    out: dict[str, Any] = {"alert_id": alert_id, "run_id": run_id, "item": d.item, "decision": d.decision}
    try:
        if d.item == "verdict":
            if d.decision == "accepted":
                verdict = d.override_verdict or ticket.get("verdict")
                if verdict not in FINAL_VERDICTS:
                    raise DecisionError("El ticket dice needs_more_info: elige el veredicto final (override_verdict)")
                conn.execute(
                    "INSERT INTO alert_history (alert_id, verdict) VALUES (?, ?) "
                    "ON CONFLICT (alert_id) DO UPDATE SET verdict = excluded.verdict",
                    (alert_id, verdict),
                )
                out["alert_history"] = verdict
            out["decision_id"] = _record(conn, alert_id, run_id, d)
        elif m := re.fullmatch(r"action:(\d+)", d.item):
            index = int(m[1])
            actions = ticket.get("recommended_actions") or []
            if index >= len(actions):
                raise DecisionError(f"El ticket no tiene la acción {index}")
            if d.override_verdict is not None:
                raise DecisionError("override_verdict solo aplica al veredicto")
            out["decision_id"] = _record(conn, alert_id, run_id, d)
            if d.decision == "accepted":
                out["execution"] = _execute(
                    conn, api, alert_id, run_id, index, actions[index], d, str(ticket.get("ticket_id") or "")
                )
        else:
            raise DecisionError("item debe ser 'verdict' o 'action:<n>'")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return out
