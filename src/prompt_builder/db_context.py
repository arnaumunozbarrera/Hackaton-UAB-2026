"""Alert context for the prompt, read from the workflow database (live alerts) instead of `docs/`.

Same `AlertContext` as `DatasetContextSource`, so the builder is unchanged. Informative logs come from the basic
checks of this alert (`src.checks.CheckResult`):

- no guard: an event explained by context (N4) without free text is set aside with its reference; explained
  events with free text and unexplained events are informative;
- any guard (high/critical, OT, G1, G2...): every event is informative, explained ones carry the guard and the
  reference, so the LLM sees both.

Dataset-wide noise stages (N1-N3) do not apply: a live alert is triaged on its own.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from ..checks import CheckResult, run_checks
from ..database.schema import ROOT
from .context import PRODUCT_SERVICES, AffectedAsset, AffectedService, AffectedUser, AlertContext, InformativeLog


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    cur = conn.execute(sql, params)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]


def guard_codes(guards: list[str]) -> str:
    """Short labels of the guards ('Severidad', 'OT', 'G1', ...)."""
    return ", ".join(dict.fromkeys(g.split(" ")[0].rstrip(":") for g in guards))


def informative_logs(
    result: CheckResult, timestamps: dict[str, str], order: list[str]
) -> tuple[list[InformativeLog], dict[str, list[str]], dict[str, str]]:
    """(informative logs, set-aside ids per stage, event -> reference) from the checks of one alert."""
    logs, aside, refs = [], [], {}
    codes = guard_codes(result.guards)
    for eid in order:
        source, ts = result.sources.get(eid, eid.split("-")[0].lower()), timestamps.get(eid, "")
        exp = result.explanations.get(eid)
        if exp is None:
            logs.append(InformativeLog(eid, source, ts, "no explicado"))
        elif result.guards:
            logs.append(InformativeLog(eid, source, ts, f"guarda {codes}, {exp.reference}"))
        elif eid in result.open_text:
            logs.append(InformativeLog(eid, source, ts, f"texto libre, {exp.reference}"))
        else:
            aside.append(eid)
            refs[eid] = exp.reference
    return logs, ({"N4": aside} if aside else {}), refs


class DatabaseContextSource:
    """`ContextSource` over the workflow database; pass the checks already run with `remember()` to reuse them."""

    def __init__(self, db_path: str | Path | None = None, product_services: dict[str, tuple[str, ...]] | None = None):
        self.db_path = Path(db_path or os.environ.get("TARVIA_DB") or ROOT / "data" / "tarvia.sqlite")
        self.conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        self.product_services = PRODUCT_SERVICES if product_services is None else product_services
        self.checks: dict[str, CheckResult] = {}

    def close(self) -> None:
        self.conn.close()

    def remember(self, result: CheckResult) -> None:
        self.checks[result.alert_id] = result

    def _hosts(self, alert_id: str) -> list[AffectedAsset]:
        rows = _rows(
            self.conn,
            "SELECT s.hostname, s.criticality, s.business_service, s.zone_id, s.type FROM alert_assets a "
            "JOIN assets s ON s.asset_id = a.asset_id WHERE a.alert_id = ? ORDER BY s.hostname",
            (alert_id,),
        )
        return [
            AffectedAsset(r["hostname"], r["criticality"] or "", r["business_service"] or "", r["zone_id"] or "",
                          r["type"] or "")
            for r in rows
        ]  # fmt: skip

    def _services(self, product: str, hosts: list[AffectedAsset]) -> list[AffectedService]:
        names = set(self.product_services.get(product, ())) | {h.business_service for h in hosts if h.business_service}
        out = []
        for name in sorted(names):
            rows = _rows(
                self.conn,
                "SELECT name, criticality, asset_references, owner_role FROM business_services WHERE name = ?",
                (name,),
            )
            out += [
                AffectedService(r["name"], r["criticality"] or "", r["asset_references"] or "", r["owner_role"] or "")
                for r in rows
            ]
        return out

    def _users(self, alert_id: str) -> list[AffectedUser]:
        rows = _rows(
            self.conn,
            "SELECT u.username, u.account_type, u.privileged, u.vip, (SELECT h.event_type FROM hr_events h "
            "WHERE h.user_id = u.user_id ORDER BY h.effective_date DESC LIMIT 1) AS hr FROM alert_users a "
            "JOIN users u ON u.user_id = a.user_id WHERE a.alert_id = ? ORDER BY u.username",
            (alert_id,),
        )
        return [
            AffectedUser(r["username"].lower(), r["account_type"] or "", bool(r["privileged"]), bool(r["vip"]),
                         r["hr"] or "")
            for r in rows
        ]  # fmt: skip

    def _entities(self, alert_id: str) -> dict[str, list[str]]:
        out: dict[str, set[str]] = {}

        def add(key: str, values: list[Any]) -> None:
            vals = {str(v) for v in values if v not in (None, "")}
            if vals:
                out.setdefault(key, set()).update(vals)

        kinds = {"ip": "ips", "domain": "domains", "url": "urls"}
        for kind, value in self.conn.execute(
            "SELECT indicator_type, value FROM alert_indicators WHERE alert_id = ?", (alert_id,)
        ):
            add(kinds.get(kind, kind + "s"), [value])
        for r in _rows(self.conn, "SELECT file_name, sha256, path FROM alert_files WHERE alert_id = ?", (alert_id,)):
            add("files", list(r.values()))
        for r in _rows(
            self.conn, "SELECT name, parent_name, command_line FROM alert_processes WHERE alert_id = ?", (alert_id,)
        ):
            add("processes", list(r.values()))
        for r in _rows(self.conn, "SELECT customer_id, role FROM alert_customers WHERE alert_id = ?", (alert_id,)):
            add("customers", list(r.values()))
        for r in _rows(
            self.conn,
            "SELECT cloud_account, identity, bucket, access_key, new_user FROM alert_cloud WHERE alert_id = ?",
            (alert_id,),
        ):
            add("cloud", list(r.values()))
        add("ai_session", [r[0] for r in self.conn.execute(
            "SELECT session_id FROM alert_ai_sessions WHERE alert_id = ?", (alert_id,))])  # fmt: skip
        return {k: sorted(v) for k, v in out.items()}

    def get(self, alert_id: str) -> AlertContext:
        rows = _rows(
            self.conn,
            "SELECT a.alert_id, a.created_at, a.rule_id, a.severity, a.description, a.evidence_json, "
            "r.name, r.source_product, r.technique_id, r.tactic, r.runbook_id FROM alerts a "
            "JOIN detection_rules r ON r.rule_id = a.rule_id WHERE a.alert_id = ?",
            (alert_id,),
        )
        if not rows:
            raise KeyError(f"unknown alert: {alert_id}")
        a = rows[0]
        result = self.checks.get(alert_id) or run_checks(self.conn, alert_id)
        events = _rows(
            self.conn,
            "SELECT e.event_id, l.timestamp FROM alert_events e LEFT JOIN logs l ON l.event_id = e.event_id "
            "WHERE e.alert_id = ? ORDER BY e.position",
            (alert_id,),
        )
        logs, aside, refs = informative_logs(
            result, {e["event_id"]: e["timestamp"] or "" for e in events}, [e["event_id"] for e in events]
        )
        hosts = self._hosts(alert_id)
        evidence = json.dumps(json.loads(a["evidence_json"] or "{}"), ensure_ascii=False)
        return AlertContext(
            alert_id, a["created_at"], a["rule_id"], a["name"], a["severity"], a["source_product"] or "",
            a["technique_id"] or "", a["tactic"] or "", a["runbook_id"] or "", a["description"] or "", evidence,
            hosts, self._services(a["source_product"] or "", hosts), [], self._users(alert_id), [],
            self._entities(alert_id), logs, aside, refs,
        )  # fmt: skip
