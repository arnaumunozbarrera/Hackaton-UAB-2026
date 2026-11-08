"""End-to-end triage over the database: one object shared by the CLI (src.main) and the web server.

sync (SOC API -> DB) -> enrich -> log selection -> embeddings -> per alert: discriminator | prompt -> LLM
-> validated ticket -> policy automation (severity guard, approvals, escalation, SLA, notifications, N1 containment)
-> triage_tickets.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..database import enrich
from ..llm_triage.client import AnthropicLLM, MockLLM, TriageResult, TriageRunner
from ..llm_triage.db_backend import DbToolBackend
from ..llm_triage.validator import validate_ticket
from ..prompt_builder import DbContextSource, PromptBuilder, PromptConfig
from ..severity import assessment_for_ticket
from . import automation, discriminator, selection, similarity, store
from .automation import PolicyAutomation

MODES = ("mock", "anthropic", "claude-code")


class TriageFlow:
    def __init__(
        self,
        db_path: str | Path | None = None,
        data_dir: str | Path = "docs",
        mode: str = "mock",
        model: str | None = None,
        progress: Callable[[str], None] = print,
        prepare: bool = True,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode}; use {', '.join(MODES)}")
        self.db_path = enrich.db_path(db_path)
        self.data = Path(data_dir)
        self.mode, self.model, self.progress = mode, model, progress
        self.lock = threading.RLock()
        self.conn = enrich.connect(self.db_path)
        if prepare:
            self.prepare()
        self.source = DbContextSource(self.conn, data_dir=self.data)
        self.builder = PromptBuilder(self.source, PromptConfig(data_dir=self.data))
        self.backend = DbToolBackend(self.db_path)
        self.runner = TriageRunner(self.builder, self.backend)
        self.policy = PolicyAutomation(self.data)
        self._api = None
        self._claude_code = None
        self.live: dict[str, Any] = {"enabled": False, "interval": 0, "batch": 0, "ticks": 0, "ingested": 0,
                                     "triaged": 0, "last_tick": None, "last_error": None, "recent": []}  # fmt: skip

    # ------------------------------------------------------------ preparation steps
    def prepare(self) -> dict[str, Any]:
        """Derived layer, log selection and embeddings for every alert that lacks them (incremental)."""
        with self.lock:
            t0 = time.monotonic()
            derived = enrich.refresh(self.conn, self.data)
            derived["sla_clock_started"] = automation.mark_received(self.conn)
            if selection.alerts_without_selection(self.conn):
                sel = selection.persist_selection(self.conn, self._noise_filter())
            else:
                sel = {}
            from ..embeddings.encoder import get_encoder

            if hasattr(self, "source"):
                self.source.reload()
                alerts = self.source.alerts
            else:
                alerts = DbContextSource(self.conn, data_dir=self.data).alerts
            if getattr(self, "_encoder", None) is None:
                self._encoder = get_encoder()
            encoder = self._encoder
            added = similarity.index_alerts(self.conn, alerts, encoder)
            derived["automation_backfilled"] = self._backfill()
            out = derived | {"selection": sel, "embeddings_added": added, "encoder": encoder.name,
                             "seconds": round(time.monotonic() - t0, 1)}  # fmt: skip
        self.progress(f"[flow] prepared: {out}")
        return out

    def filter_scope(self) -> str:
        """'dataset' (default: every alert of docs/) or 'database' (only the alerts in this database, demo copies)."""
        try:
            row = self.conn.execute("SELECT value FROM pipeline_meta WHERE key = 'filter_scope'").fetchone()
        except sqlite3.OperationalError:
            return "dataset"
        return row[0] if row and row[0] in ("dataset", "database") else "dataset"

    def _noise_filter(self):  # noqa: ANN202
        """Log noise filter result, cached while its alert universe does not change."""
        from ..log_noise_discard import run_filter
        from ..log_noise_discard.loaders import load_alerts

        scope, alerts = self.filter_scope(), None
        if scope == "database":
            ids = {r[0] for r in self.conn.execute("SELECT alert_id FROM alerts")}
            alerts = {k: v for k, v in load_alerts(self.data).items() if k in ids}
            key = ("database", frozenset(alerts))
        else:
            key = ("dataset",)
        if getattr(self, "_filter", None) is None or getattr(self, "_filter_key", None) != key:
            self._filter = run_filter(self.data, alerts=alerts)
            self._filter_key = key
            self.progress(
                f"[flow] log filter recomputed over {'the dataset' if alerts is None else len(alerts)} alerts"
            )
        return self._filter

    def _backfill(self) -> int:
        """Policy automation for tickets stored before it existed (no containment is executed retroactively)."""
        rows = self.conn.execute(
            "SELECT alert_id, ticket_json FROM triage_tickets WHERE alert_id NOT IN (SELECT alert_id FROM ticket_automation)"
        ).fetchall()
        policy = getattr(self, "policy", None) or PolicyAutomation(self.data)
        for alert_id, raw in rows:
            ticket = json.loads(raw or "{}")
            record = policy.apply(self.conn, alert_id, ticket)
            if record["changes"]:
                self.conn.execute(
                    "UPDATE triage_tickets SET ticket_json = ?, severity = ?, escalate = ? WHERE alert_id = ?",
                    (json.dumps(ticket, ensure_ascii=False), ticket.get("severity"),
                     int(bool((ticket.get("escalation") or {}).get("escalate"))), alert_id),
                )  # fmt: skip
            policy.save(self.conn, record)
        return len(rows)

    # ------------------------------------------------------------ policy actions
    @property
    def api(self):  # noqa: ANN201
        if self._api is None:
            from ..soc_api import SocApi

            self._api = SocApi(timeout=5)
        return self._api

    def run_actions(self, alert_id: str, plan: list[dict[str, Any]], ticket: dict[str, Any] | None, mode: str,
                    approver: str = "") -> list[dict[str, Any]]:  # fmt: skip
        """Execute containment actions on the SOC API (network outside the lock) and record each result."""
        ticket_id = str((ticket or {}).get("ticket_id") or alert_id)
        out = []
        for action in plan:
            if action["action"] == "manual":
                out.append(
                    action | {"status": "manual", "detail": "sin acción equivalente en la API: la ejecuta el operador"}
                )
                continue
            if action["action"] == "ot":
                with self.lock:
                    out.append(automation.record_action(self.conn, alert_id, action | {"action": "escalate_ot"}, mode,
                               "blocked", "OT: el SOC solo escala a Operaciones"))  # fmt: skip
                continue
            with self.lock:
                if automation.already_done(self.conn, alert_id, action["action"], action["target"]):
                    continue
            status, detail, token = automation.execute(self.api, action, ticket_id, approver)
            with self.lock:
                out.append(automation.record_action(self.conn, alert_id, action, mode, status, detail, token))
        return out

    def after_decision(self, alert_id: str, decision: str, operator: str = "") -> dict[str, Any]:
        """Approve: run the approved containment on the SOC API. Escalate: notify N2 (simulated outbox)."""
        with self.lock:
            row = self.conn.execute("SELECT ticket_json FROM triage_tickets WHERE alert_id = ?", (alert_id,)).fetchone()
        ticket = json.loads(row[0]) if row else {}
        if decision == "approve":
            return {
                "actions": self.run_actions(alert_id, automation.approved_plan(ticket), ticket, "approved", operator)
            }
        if decision == "escalate":
            with self.lock:
                self.conn.execute(
                    "INSERT OR IGNORE INTO soc_notifications (alert_id, recipient, channel, reason, status, created_at) "
                    "VALUES (?, 'N2', 'correo (simulado)', ?, 'queued', ?)",
                    (alert_id, f"escalado manual por {operator or 'el operador'}", store.now()),
                )
                self.conn.commit()
            return {"notified": ["N2"]}
        return {}

    def sla_sweep(self) -> list[str]:
        """Notify the SOC lead of pending tickets whose SLA deadline has passed (once per alert)."""
        with self.lock:
            return automation.sla_breaches(self.conn)

    def sync(self, max_alerts: int | None = None) -> dict[str, Any]:
        """Pull new alerts (at most `max_alerts`) and their events from the SOC API, then prepare them."""
        from ..database.sync import AlertFeed

        added: list[str] = []
        with AlertFeed(self.db_path, progress=self.progress) as feed:
            while (max_alerts is None or len(added) < max_alerts) and (alert := feed.next_alert()) is not None:
                if feed.store(alert):
                    added.append(alert["alert_id"])
            summary = dict(feed.summary)
        out = self.prepare() if added or max_alerts is None else {}
        return {"sync": summary, "prepare": out, "added": added}

    # ------------------------------------------------------------ live mode
    def start_live(self, interval: float = 10, batch: int = 3) -> None:
        """Background loop: every `interval` s pull up to `batch` new alerts from the SOC API and triage them."""
        if self.live["enabled"]:
            return
        self.live.update(enabled=True, interval=interval, batch=batch)

        def loop() -> None:
            while self.live["enabled"]:
                try:
                    out = self.sync(max_alerts=batch)
                    self.live["ticks"] += 1
                    self.live["ingested"] += len(out["added"])
                    for alert_id in out["added"]:
                        res = self.triage(alert_id)
                        self.live["triaged"] += 1
                        ticket = res["result"]["ticket"] or {}
                        entry = {"alert_id": alert_id, "route": res["route"], "verdict": ticket.get("verdict"),
                                 "severity": ticket.get("severity"), "at": store.now()}  # fmt: skip
                        self.live["recent"] = [entry, *self.live["recent"]][:20]
                    self.sla_sweep()
                    self.live.update(last_tick=store.now(), last_error=None, queue_exhausted=not out["added"])
                except Exception as exc:  # API down, rate limit...: keep looping
                    self.live.update(last_tick=store.now(), last_error=f"{type(exc).__name__}: {exc}")
                time.sleep(interval)

        threading.Thread(target=loop, daemon=True, name="live-sync").start()

    def stop_live(self) -> None:
        self.live["enabled"] = False

    # ------------------------------------------------------------ triage
    def pending(self, limit: int | None = None) -> list[str]:
        """Alerts without a ticket, most severe rule first, then oldest."""
        sql = (
            "SELECT alert_id FROM alerts WHERE alert_id NOT IN (SELECT alert_id FROM triage_tickets) "
            "AND alert_id NOT IN (SELECT alert_id FROM backlog_closed) ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, created_at"
        )
        rows = [r[0] for r in self.conn.execute(sql + (f" LIMIT {int(limit)}" if limit else ""))]
        return rows

    def _llm_result(
        self, alert_id: str, note: str, log: list[dict[str, Any]] | None, mode: str | None = None
    ) -> TriageResult:
        mode = mode or self.mode
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode}")
        if mode == "claude-code":
            if self._claude_code is None:
                from ..llm_triage.claude_code import ClaudeCodeRunner

                ClaudeCodeRunner.ensure_subscription_auth()
                self._claude_code = ClaudeCodeRunner(self.builder, self.backend, self.model)
            return self._claude_code.run(alert_id, analyst_note=note, log=log)
        llm = MockLLM(self.builder.build(alert_id)) if mode == "mock" else AnthropicLLM(self.model)
        return self.runner.run(alert_id, llm, note, log=log)

    def triage(self, alert_id: str, note: str = "", log: list[dict[str, Any]] | None = None,
               force_llm: bool = False, mode: str | None = None) -> dict[str, Any]:  # fmt: skip
        """Triage one alert and persist the ticket. Returns {"route", "result", "prompt"}."""
        if alert_id not in self.source.alerts:
            raise KeyError(alert_id)
        started = time.monotonic()
        with self.lock:
            ctx = self.source.get(alert_id)
            decision = discriminator.decide(self.conn, alert_id, ctx)
            if decision.route == "discriminator" and not force_llm and not note.strip():
                discriminator_metadata = self.builder.build(alert_id).metadata
                explained = self.conn.execute(
                    "SELECT event_id,reason,reference FROM alert_log_selection WHERE alert_id=? AND state='N4' ORDER BY event_id",
                    (alert_id,),
                ).fetchall()
        if decision.route == "discriminator" and not force_llm and not note.strip():
            ticket = decision.ticket or {}
            ticket["triage_seconds"] = round(time.monotonic() - started, 3)
            errors = validate_ticket(ticket, self.builder.output_schema, alert_id)
            entry = {"type": "discriminador", "output": decision.reason, "references": decision.references}
            if log is not None:
                log.append(entry)
            result = TriageResult(alert_id, "discriminator", ticket, not errors, errors, 1, [entry], {},
                                  round(time.monotonic() - started, 3))  # fmt: skip
            if result.valid:
                result.severity_assessment = assessment_for_ticket(discriminator_metadata, ticket, "discriminator")
                for eid, reason, reference in explained:
                    result.severity_assessment["evidence"].append(
                        {
                            "condition": "existing_discriminator_context",
                            "status": "confirmed",
                            "source": "alert_log_selection",
                            "source_key": f"{alert_id}:{eid}",
                            "event_id": eid,
                            "reference": reference or "contexto",
                            "finding": reason or "Contexto utilizado por el discriminador existente",
                            "details": {"reason": reason},
                        }
                    )
        else:
            if log is not None:
                log.append({"type": "discriminador", "output": f"al LLM: {decision.reason}"})
            result = self._llm_result(alert_id, note, log, mode)
            if isinstance(result.ticket, dict) and result.valid:
                result.ticket.setdefault("triage_seconds", result.elapsed_s)
        route = "discriminator" if result.model == "discriminator" else "llm"
        with self.lock:
            record = self.policy.apply(self.conn, alert_id, result.ticket)
            entry = {"type": "politica", "output": "; ".join(c["detail"] for c in record["changes"])
                     or "sin cambios: el ticket ya cumple la política", "sla": record["sla_due_at"]}  # fmt: skip
            result.transcript.append(entry)
            if log is not None and log is not result.transcript:
                log.append(entry)
            store.save_ticket(self.conn, alert_id, result.ticket, valid=result.valid, route=route, model=result.model,
                              errors=result.errors, attempts=result.attempts, usage=result.usage,
                              transcript=result.transcript, elapsed_s=result.elapsed_s,
                              severity_assessment=result.severity_assessment)  # fmt: skip
            self.policy.save(self.conn, record)
        if result.valid and record["plan"]:
            self.run_actions(alert_id, record["plan"], result.ticket, "auto")
        print(f"[flow] {alert_id}: route={route} valid={result.valid} verdict="
              f"{(result.ticket or {}).get('verdict')} {result.elapsed_s}s", file=sys.stderr, flush=True)  # fmt: skip
        return {"route": route, "decision_reason": decision.reason, "result": result.to_dict()}

    def run_batch(self, limit: int | None = None, alert_ids: list[str] | None = None,
                  on_done: Callable[[dict], None] | None = None) -> dict[str, Any]:  # fmt: skip
        ids = alert_ids or self.pending(limit)
        counts: dict[str, int] = {"llm": 0, "discriminator": 0, "errors": 0, "invalid": 0}
        for alert_id in ids:
            try:
                out = self.triage(alert_id)
                counts[out["route"]] += 1
                counts["invalid"] += 0 if out["result"]["valid"] else 1
                if on_done:
                    on_done(out)
            except Exception as exc:  # one failing alert never stops the batch
                counts["errors"] += 1
                self.progress(f"[flow] {alert_id}: {type(exc).__name__}: {exc}")
        return {"processed": len(ids)} | counts

    def close(self) -> None:
        self.conn.close()
