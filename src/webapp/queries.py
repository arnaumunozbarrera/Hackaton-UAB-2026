"""Read side of the web UI: alert queue with derived status, alert detail, decision history and stats.

Status of an alert (latest runs and decisions win):

- `accepted` / `rejected`: the analyst's last decision on the verdict;
- `in_llm`: an LLM run is in progress;
- `awaiting_analyst`: a ticket exists (LLM, or auto ticket of the checks) and nobody decided yet;
  `auto_closed` is reported for the auto-ticket case so the queue can show it apart;
- `llm_error`: the last LLM run failed (or ended without a storable ticket);
- `pending_llm`: the checks kept it and no LLM ran (workflow run with `--llm none`);
- `new`: stored, no triage yet.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..checks.db_events import log_record

STATUSES = ("new", "pending_llm", "in_llm", "llm_error", "auto_closed", "awaiting_analyst", "accepted", "rejected")


def rows(conn: sqlite3.Connection, sql: str, params: Any = ()) -> list[dict[str, Any]]:
    cur = conn.execute(sql, params)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, r, strict=True)) for r in cur.fetchall()]


def _json(value: str | None, default: Any = None) -> Any:
    return json.loads(value) if value else default


def _latest_by_alert(conn: sqlite3.Connection, sql: str, alert_id: str | None) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for r in rows(conn, sql, {"1": alert_id}):
        out[r["alert_id"]] = r  # rows ordered by id ascending: the last one wins
    return out


def derive_status(check: dict | None, llm: dict | None, ticket: dict | None, verdict: dict | None) -> str:
    if verdict and (ticket is None or verdict["run_id"] in (None, ticket["run_id"])):
        return verdict["decision"]  # a decision on an older ticket does not cover a newer run
    if llm and llm["status"] == "running":
        return "in_llm"
    if llm and (llm["status"] == "error" or ticket is None or ticket["run_id"] != llm["run_id"]):
        return "llm_error"
    if ticket:
        return "auto_closed" if ticket["stage"] == "auto_check" else "awaiting_analyst"
    if check:
        return "pending_llm" if check["status"] == "done" else "llm_error"
    return "new"


def queue(conn: sqlite3.Connection, alert_id: str | None = None) -> list[dict[str, Any]]:
    """Every stored alert (or only `alert_id`) with its derived status and latest ticket summary, newest first."""
    checks = _latest_by_alert(
        conn,
        "SELECT * FROM triage_runs WHERE stage = 'auto_check' AND (?1 IS NULL OR alert_id = ?1) ORDER BY run_id",
        alert_id,
    )
    llms = _latest_by_alert(
        conn,
        "SELECT * FROM triage_runs WHERE stage = 'llm' AND (?1 IS NULL OR alert_id = ?1) ORDER BY run_id",
        alert_id,
    )
    tickets = _latest_by_alert(
        conn,
        "SELECT t.run_id, t.alert_id, t.ticket_id, t.verdict, t.severity, t.ticket_confidence, t.valid, r.stage, "
        "json_extract(t.ticket_json, '$.title') AS title FROM triage_tickets t "
        "JOIN triage_runs r ON r.run_id = t.run_id WHERE (?1 IS NULL OR t.alert_id = ?1) ORDER BY t.run_id",
        alert_id,
    )
    verdicts = _latest_by_alert(
        conn,
        "SELECT * FROM analyst_decisions WHERE item = 'verdict' AND (?1 IS NULL OR alert_id = ?1) ORDER BY decision_id",
        alert_id,
    )
    alerts = rows(
        conn,
        "SELECT a.alert_id, a.created_at, a.rule_id, a.severity, r.name AS rule_name, r.base_severity, r.runbook_id, "
        "r.source_product, (SELECT group_concat(s.hostname, ', ') FROM alert_assets x JOIN assets s "
        "ON s.asset_id = x.asset_id WHERE x.alert_id = a.alert_id) AS hosts, (SELECT group_concat(u.username, ', ') "
        "FROM alert_users x JOIN users u ON u.user_id = x.user_id WHERE x.alert_id = a.alert_id) AS users "
        "FROM alerts a JOIN detection_rules r ON r.rule_id = a.rule_id WHERE (?1 IS NULL OR a.alert_id = ?1) "
        "ORDER BY a.created_at DESC",
        {"1": alert_id},
    )
    out = []
    for a in alerts:
        aid = a["alert_id"]
        check, llm, ticket, verdict = checks.get(aid), llms.get(aid), tickets.get(aid), verdicts.get(aid)
        out.append(
            a
            | {
                "status": derive_status(check, llm, ticket, verdict),
                "ticket": ticket
                and {k: ticket[k] for k in ("run_id", "ticket_id", "verdict", "severity", "title")}
                | {
                    "confidence": ticket["ticket_confidence"],
                    "valid": bool(ticket["valid"]),
                    "origin": ticket["stage"],
                },
                "human_verdict": verdict and (verdict["override_verdict"] or (ticket or {}).get("verdict")),
                "analyst": verdict and verdict["analyst"],
            }
        )
    return out


def _run(r: dict[str, Any]) -> dict[str, Any]:
    return r | {
        "valid": None if r["valid"] is None else bool(r["valid"]),
        "errors": _json(r.pop("errors_json"), []),
        "usage": _json(r.pop("usage_json"), {}),
        "transcript": _json(r.pop("transcript_json"), []),
    }


def detail(conn: sqlite3.Connection, alert_id: str) -> dict[str, Any] | None:
    """Everything the detail view shows for one alert; None if the alert is not stored."""
    found = rows(
        conn,
        "SELECT a.*, r.name AS rule_name, r.base_severity, r.runbook_id, r.source_product, r.tactic, r.technique_id, "
        "r.technique_name FROM alerts a JOIN detection_rules r ON r.rule_id = a.rule_id WHERE a.alert_id = ?",
        (alert_id,),
    )
    if not found:
        return None
    alert = found[0]
    alert["evidence"] = _json(alert.pop("evidence_json"), {})
    entities = {
        "hosts": rows(
            conn,
            "SELECT s.hostname, s.ip, s.criticality, s.zone_id, s.business_service FROM alert_assets x "
            "JOIN assets s ON s.asset_id = x.asset_id WHERE x.alert_id = ?",
            (alert_id,),
        ),
        "users": rows(
            conn,
            "SELECT u.username, u.upn, u.department, u.account_type, u.privileged, u.vip FROM alert_users x "
            "JOIN users u ON u.user_id = x.user_id WHERE x.alert_id = ?",
            (alert_id,),
        ),
        "indicators": rows(
            conn,
            "SELECT i.indicator_type, i.value, t.reputation FROM alert_indicators i LEFT JOIN threat_intelligence t "
            "ON t.value = i.value COLLATE NOCASE WHERE i.alert_id = ?",
            (alert_id,),
        ),
        "files": rows(conn, "SELECT file_name, sha256, path FROM alert_files WHERE alert_id = ?", (alert_id,)),
        "processes": rows(
            conn, "SELECT name, parent_name, command_line FROM alert_processes WHERE alert_id = ?", (alert_id,)
        ),
        "customers": rows(conn, "SELECT customer_id, role FROM alert_customers WHERE alert_id = ?", (alert_id,)),
    }
    event_ids = [r[0] for r in conn.execute(
        "SELECT event_id FROM alert_events WHERE alert_id = ? ORDER BY position", (alert_id,))]  # fmt: skip
    events = []
    for eid in event_ids:
        rec = log_record(conn, eid)
        events.append({"event_id": eid, "source": rec[0], "event": rec[1]} if rec else {"event_id": eid})
    runs = [_run(r) for r in rows(conn, "SELECT * FROM triage_runs WHERE alert_id = ? ORDER BY run_id", (alert_id,))]
    check_rows = rows(
        conn,
        "SELECT c.* FROM triage_checks c JOIN triage_runs r ON r.run_id = c.run_id WHERE r.alert_id = ? "
        "ORDER BY c.run_id DESC LIMIT 1",
        (alert_id,),
    )
    checks = None
    if check_rows:
        c = check_rows[0]
        checks = {
            "run_id": c["run_id"], "discard": bool(c["discard"]), "verdict": c["verdict"], "severity": c["severity"],
            "reasons": _json(c["reasons_json"], []), "references": _json(c["references_json"], []),
            "guards": _json(c["guards_json"], []),
        }  # fmt: skip
    llm_runs = [r for r in runs if r["stage"] == "llm"]
    llm = llm_runs[-1] if llm_runs else None
    requests = []
    if llm:
        requests = [
            r | {"consultas": _json(r.pop("consultas_json"), []), "rows": _json(r.pop("rows_json"), []),
                 "is_error": bool(r["is_error"])}
            for r in rows(conn, "SELECT * FROM triage_context_requests WHERE run_id = ? ORDER BY n", (llm["run_id"],))
        ]  # fmt: skip
    ticket_rows = rows(
        conn,
        "SELECT t.*, r.stage FROM triage_tickets t JOIN triage_runs r ON r.run_id = t.run_id WHERE t.alert_id = ? "
        "ORDER BY t.run_id DESC LIMIT 1",
        (alert_id,),
    )
    ticket = None
    if ticket_rows:
        t = ticket_rows[0]
        ticket = {"run_id": t["run_id"], "origin": t["stage"], "valid": bool(t["valid"]), "created_at": t["created_at"],
                  "ticket": _json(t["ticket_json"], {})}  # fmt: skip
    decisions = rows(conn, "SELECT * FROM analyst_decisions WHERE alert_id = ? ORDER BY decision_id", (alert_id,))
    executed = [
        r | {"api_result": _json(r.pop("api_result_json"), None)}
        for r in rows(conn, "SELECT * FROM executed_actions WHERE alert_id = ? ORDER BY execution_id", (alert_id,))
    ]
    human = rows(conn, "SELECT verdict FROM alert_history WHERE alert_id = ?", (alert_id,))
    status = next((q["status"] for q in queue(conn, alert_id)), "new")
    return {
        "alert": alert, "entities": entities, "events": events, "status": status, "checks": checks, "llm": llm,
        "context_requests": requests, "ticket": ticket, "decisions": decisions, "executed_actions": executed,
        "runs": [{k: v for k, v in r.items() if k != "transcript"} for r in runs],
        "alert_history": human[0]["verdict"] if human else None,
    }  # fmt: skip


def decisions(conn: sqlite3.Connection, limit: int = 500) -> list[dict[str, Any]]:
    """Analyst decisions, newest first, with the model's verdict they reviewed and any executed action."""
    return rows(
        conn,
        "SELECT d.*, t.verdict AS ai_verdict, t.severity AS ai_severity, r.stage AS origin, r.model, "
        "a.rule_id, dr.name AS rule_name, CASE WHEN d.item GLOB 'action:*' THEN json_extract(t.ticket_json, "
        "'$.recommended_actions[' || substr(d.item, 8) || '].action') END AS action, "
        "CASE WHEN d.item GLOB 'action:*' THEN json_extract(t.ticket_json, '$.recommended_actions[' || "
        "substr(d.item, 8) || '].target') END AS target, (SELECT e.status FROM executed_actions e WHERE "
        "e.run_id = d.run_id AND 'action:' || e.action_index = d.item ORDER BY e.execution_id DESC LIMIT 1) "
        "AS execution_status FROM analyst_decisions d JOIN alerts a ON a.alert_id = d.alert_id "
        "JOIN detection_rules dr ON dr.rule_id = a.rule_id LEFT JOIN triage_tickets t ON t.run_id = d.run_id "
        "LEFT JOIN triage_runs r ON r.run_id = d.run_id ORDER BY d.decision_id DESC LIMIT ?",
        (limit,),
    )


def stats(conn: sqlite3.Connection) -> dict[str, Any]:
    q = queue(conn)
    by_status = {s: 0 for s in STATUSES}
    for a in q:
        by_status[a["status"]] += 1
    verdicts: dict[str, int] = {}
    for a in q:
        if a["ticket"]:
            verdicts[a["ticket"]["verdict"]] = verdicts.get(a["ticket"]["verdict"], 0) + 1
    llm = rows(
        conn,
        "SELECT COUNT(*) AS runs, AVG(elapsed_s) AS avg_s, SUM(valid) AS valid, "
        "SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS errors, "
        "SUM(COALESCE(json_extract(usage_json, '$.input_tokens'), 0)) AS input_tokens, "
        "SUM(COALESCE(json_extract(usage_json, '$.output_tokens'), 0)) AS output_tokens "
        "FROM triage_runs WHERE stage = 'llm'",
    )[0]
    decided = rows(
        conn,
        "SELECT COUNT(*) AS total, SUM(CASE WHEN decision = 'accepted' AND override_verdict IS NULL THEN 1 ELSE 0 END) "
        "AS agreed FROM analyst_decisions WHERE item = 'verdict'",
    )[0]
    actions = dict(conn.execute("SELECT status, COUNT(*) FROM executed_actions GROUP BY status").fetchall())
    daily = rows(
        conn,
        "SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS alerts FROM alerts GROUP BY day ORDER BY day",
    )
    return {
        "alerts": len(q), "by_status": by_status, "verdicts": verdicts, "llm": llm,
        "auto_closed": sum(1 for a in q if a["ticket"] and a["ticket"]["origin"] == "auto_check"),
        "decisions": decided, "executed_actions": actions, "daily": daily,
    }  # fmt: skip
