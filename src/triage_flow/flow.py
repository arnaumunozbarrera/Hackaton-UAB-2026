"""End-to-end triage over the database: one object shared by the CLI (src.main) and the web server.

sync (SOC API -> DB) -> enrich -> log selection -> embeddings -> per alert: discriminator | prompt -> LLM
-> validated ticket in triage_tickets.
"""

from __future__ import annotations

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
from . import discriminator, selection, similarity, store

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
        self._claude_code = None
        self.live: dict[str, Any] = {"enabled": False, "interval": 0, "batch": 0, "ticks": 0, "ingested": 0,
                                     "triaged": 0, "last_tick": None, "last_error": None, "recent": []}  # fmt: skip

    # ------------------------------------------------------------ preparation steps
    def prepare(self) -> dict[str, Any]:
        """Derived layer, log selection and embeddings for every alert that lacks them (incremental)."""
        with self.lock:
            t0 = time.monotonic()
            derived = enrich.refresh(self.conn, self.data)
            if selection.alerts_without_selection(self.conn):
                if getattr(self, "_filter", None) is None:
                    from ..log_noise_discard import run_filter

                    self._filter = run_filter(self.data)  # once per process: the dataset does not change
                sel = selection.persist_selection(self.conn, self._filter)
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
            out = derived | {"selection": sel, "embeddings_added": added, "encoder": encoder.name,
                             "seconds": round(time.monotonic() - t0, 1)}  # fmt: skip
        self.progress(f"[flow] prepared: {out}")
        return out

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
            "SELECT alert_id FROM alerts WHERE alert_id NOT IN (SELECT alert_id FROM triage_tickets) ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, created_at"
        )
        rows = [r[0] for r in self.conn.execute(sql + (f" LIMIT {int(limit)}" if limit else ""))]
        return rows

    def _llm_result(self, alert_id: str, note: str, log: list[dict[str, Any]] | None) -> TriageResult:
        if self.mode == "claude-code":
            if self._claude_code is None:
                from ..llm_triage.claude_code import ClaudeCodeRunner

                ClaudeCodeRunner.ensure_subscription_auth()
                self._claude_code = ClaudeCodeRunner(self.builder, self.backend, self.model)
            return self._claude_code.run(alert_id, analyst_note=note, log=log)
        llm = MockLLM(self.builder.build(alert_id)) if self.mode == "mock" else AnthropicLLM(self.model)
        return self.runner.run(alert_id, llm, note, log=log)

    def triage(self, alert_id: str, note: str = "", log: list[dict[str, Any]] | None = None,
               force_llm: bool = False) -> dict[str, Any]:  # fmt: skip
        """Triage one alert and persist the ticket. Returns {"route", "result", "prompt"}."""
        if alert_id not in self.source.alerts:
            raise KeyError(alert_id)
        started = time.monotonic()
        with self.lock:
            ctx = self.source.get(alert_id)
            decision = discriminator.decide(self.conn, alert_id, ctx)
        if decision.route == "discriminator" and not force_llm and not note.strip():
            ticket = decision.ticket or {}
            ticket["triage_seconds"] = round(time.monotonic() - started, 3)
            errors = validate_ticket(ticket, self.builder.output_schema, alert_id)
            entry = {"type": "discriminador", "output": decision.reason, "references": decision.references}
            if log is not None:
                log.append(entry)
            result = TriageResult(alert_id, "discriminator", ticket, not errors, errors, 1, [entry], {},
                                  round(time.monotonic() - started, 3))  # fmt: skip
        else:
            if log is not None:
                log.append({"type": "discriminador", "output": f"al LLM: {decision.reason}"})
            result = self._llm_result(alert_id, note, log)
            if isinstance(result.ticket, dict) and result.valid:
                result.ticket.setdefault("triage_seconds", result.elapsed_s)
        route = "discriminator" if result.model == "discriminator" else "llm"
        with self.lock:
            store.save_ticket(self.conn, alert_id, result.ticket, valid=result.valid, route=route, model=result.model,
                              errors=result.errors, attempts=result.attempts, usage=result.usage,
                              transcript=result.transcript, elapsed_s=result.elapsed_s)  # fmt: skip
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
