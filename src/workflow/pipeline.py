"""Per-alert triage after ingestion: basic checks -> (auto ticket | prompt + LLM loop) -> stored results.

    triage = Triage("data/tarvia.sqlite", api=SocApi(), llm_mode="mock")
    outcome = triage.process("ALR-20261009-011791")

Each alert gets its own runs in `triage_runs`: one `auto_check` run (checks + auto ticket when discarded) and, if
kept and an LLM is configured, one `llm` run (transcript, type-2 requests, validated ticket). Nothing here acts on
anything: containment only happens in the web UI after an analyst approves it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..checks import ApiFacts, DbFacts, auto_ticket, load_context, load_ticket_schema, run_checks
from ..database.schema import ROOT
from ..llm_triage.client import AnthropicLLM, MockLLM, TriageRunner
from ..llm_triage.db_backend import DatabaseToolBackend
from ..llm_triage.openai_compat import OpenAICompatibleLLM
from ..llm_triage.validator import validate_ticket
from ..prompt_builder import DatabaseContextSource, PromptBuilder, runbooks_from_db
from . import store

LLM_MODES = ("anthropic", "claude-code", "openai", "mock", "none")


@dataclass
class Outcome:
    """What happened to one alert (also printed by the CLI)."""

    alert_id: str
    status: str  # auto_closed | llm_done | llm_invalid | llm_error | pending_llm
    verdict: str | None = None
    severity: str | None = None
    runs: list[int] = field(default_factory=list)
    detail: str = ""


def default_db_path() -> Path:
    return Path(os.environ.get("TARVIA_DB") or ROOT / "data" / "tarvia.sqlite")


class Triage:
    """Runs the post-ingestion stages for stored alerts. One instance per process; not thread-safe."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        api: Any = None,
        llm_mode: str = "none",
        model: str | None = None,
        max_context_requests: int = 6,
        max_repairs: int = 2,
    ) -> None:
        if llm_mode not in LLM_MODES:
            raise ValueError(f"llm_mode must be one of {LLM_MODES}")
        self.db_path = Path(db_path or default_db_path())
        self.llm_mode, self.model = llm_mode, model
        self.conn = store.connect(self.db_path)
        self.base = load_context(self.conn)
        db_facts = DbFacts(self.conn)
        self.facts = ApiFacts(api, db_facts) if api is not None and hasattr(api, "search_logs") else db_facts
        self.schema = load_ticket_schema()
        self.source = DatabaseContextSource(self.db_path)
        self.builder = PromptBuilder(self.source, runbooks=runbooks_from_db(self.source.conn))
        self.backend: DatabaseToolBackend | None = None
        self.runner: Any = None
        if llm_mode != "none":
            self.backend = DatabaseToolBackend(self.db_path)
            if llm_mode == "claude-code":
                from ..llm_triage.claude_code import ClaudeCodeRunner

                self.runner = ClaudeCodeRunner(
                    self.builder, self.backend, model=model, max_repairs=max_repairs,
                    max_context_requests=max_context_requests,
                )  # fmt: skip
            else:
                self.runner = TriageRunner(
                    self.builder, self.backend, max_repairs=max_repairs, max_context_requests=max_context_requests
                )
        self._anthropic: AnthropicLLM | None = None
        self._openai: OpenAICompatibleLLM | None = None

    def close(self) -> None:
        self.source.close()
        if self.backend is not None:
            self.backend.close()
        self.conn.close()

    def __enter__(self) -> Triage:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ stages
    def check(self, alert_id: str) -> tuple[int, Any]:
        """Basic checks (+ auto ticket when discarded), stored as an `auto_check` run."""
        run_id = store.start_run(self.conn, alert_id, "auto_check", "reglas")
        try:
            result = run_checks(self.conn, alert_id, base=self.base, facts=self.facts)
            store.save_checks(self.conn, run_id, result)
            errors: list[str] = []
            if result.discard:
                ticket = auto_ticket(self.conn, result)
                errors = validate_ticket(ticket, self.schema, alert_id)
                store.save_ticket(self.conn, run_id, alert_id, ticket, not errors)
            store.finish_run(self.conn, run_id, "done", valid=not errors, errors=errors, transcript=[])
        except Exception as exc:
            self.conn.rollback()
            store.finish_run(self.conn, run_id, "error", valid=False, errors=[f"{type(exc).__name__}: {exc}"])
            raise
        return run_id, result

    def _llm(self, alert_id: str) -> Any:
        if self.llm_mode == "mock":
            return MockLLM(self.builder.build(alert_id))
        if self.llm_mode == "anthropic":
            self._anthropic = self._anthropic or AnthropicLLM(model=self.model)
            return self._anthropic
        if self.llm_mode == "openai":
            self._openai = self._openai or OpenAICompatibleLLM(model=self.model)
            return self._openai
        return None  # claude-code: the runner drives the CLI itself

    def triage_llm(self, alert_id: str, analyst_note: str = "") -> tuple[int, Any]:
        """Prompt + LLM loop for a kept alert, stored as an `llm` run. Errors are stored, then re-raised."""
        label = {"mock": "mock", "claude-code": self.model or "claude-code", "openai": self.model or "openai"}.get(
            self.llm_mode
        )
        run_id = store.start_run(self.conn, alert_id, "llm", label or self.model or "anthropic")
        log: list[dict[str, Any]] = []
        try:
            result = self.runner.run(alert_id, llm=self._llm(alert_id), analyst_note=analyst_note, log=log)
        except Exception as exc:
            store.finish_run(self.conn, run_id, "error", valid=False, errors=[f"{type(exc).__name__}: {exc}"],
                             transcript=_slim(log))  # fmt: skip
            raise
        store.save_context_requests(self.conn, run_id, result.transcript)
        transcript = _slim(result.transcript)
        if store.storable(result.ticket):
            store.save_ticket(self.conn, run_id, alert_id, result.ticket, result.valid)
        elif result.ticket is not None:
            transcript.append({"type": "ticket_no_almacenable", "ticket": result.ticket})
        conn = self.conn
        conn.execute("UPDATE triage_runs SET model = ? WHERE run_id = ?", (result.model, run_id))
        store.finish_run(conn, run_id, "done", valid=result.valid, errors=result.errors, usage=result.usage,
                         elapsed_s=result.elapsed_s, transcript=transcript)  # fmt: skip
        return run_id, result

    def process(self, alert_id: str) -> Outcome:
        """All post-ingestion stages for one stored alert."""
        check_run, checks = self.check(alert_id)
        if checks.discard:
            return Outcome(alert_id, "auto_closed", checks.verdict, checks.severity, [check_run],
                           "; ".join(checks.references))  # fmt: skip
        if self.runner is None:
            return Outcome(alert_id, "pending_llm", runs=[check_run], detail="; ".join(checks.guards))
        self.source.remember(checks)
        try:
            llm_run, result = self.triage_llm(alert_id)
        except Exception as exc:
            return Outcome(alert_id, "llm_error", runs=[check_run], detail=f"{type(exc).__name__}: {exc}")
        ticket = result.ticket if isinstance(result.ticket, dict) else {}
        return Outcome(
            alert_id, "llm_done" if result.valid else "llm_invalid", ticket.get("verdict"), ticket.get("severity"),
            [check_run, llm_run], "; ".join(result.errors),
        )  # fmt: skip


def _slim(transcript: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Transcript without the full query rows (those are stored in triage_context_requests.rows_json)."""
    return [{k: v for k, v in e.items() if k != "resultados"} for e in transcript]
