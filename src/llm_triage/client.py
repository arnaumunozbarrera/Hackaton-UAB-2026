"""LLM triage loop against the Anthropic Messages API, with a mock model for offline use.

Why: one loop sends the prompt package, answers `consultar_bd` calls through a backend (dataset today, database
later) and forces the result through the `emitir_ticket` tool, whose input schema is the ticket schema. Every
ticket is validated (schema + policy); an invalid one is sent back to the model as a tool error, up to
`max_repairs` times, so the caller always receives the same format or an explicit failure.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..prompt_builder import PromptBuilder, PromptPackage
from ..prompt_builder.tools import TOOL_NAME
from .validator import tool_schema, validate_ticket

TICKET_TOOL = "emitir_ticket"
DEFAULT_MODEL = "claude-sonnet-5-5"
RESULT_PREVIEW = 6000
FINAL_INSTRUCTION = "\nEntrega: cuando termines, llama a la herramienta emitir_ticket con el ticket completo. Es la única salida válida."


class LLM(Protocol):
    def create(self, **kwargs: Any) -> dict[str, Any]: ...


def load_env(path: str | Path = ".env") -> None:
    """Minimal .env reader (KEY=VALUE lines) that never overrides existing variables."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() and not key.strip().startswith("#") and value.strip():
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


class AnthropicLLM:
    """Thin wrapper over anthropic.Anthropic().messages.create returning plain dicts."""

    def __init__(self, model: str | None = None, api_key: str | None = None) -> None:
        import anthropic  # imported lazily: tests and mock mode do not need the SDK

        self.model = model or os.environ.get("TARVIA_LLM_MODEL", DEFAULT_MODEL)
        self.client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))

    def create(self, **kwargs: Any) -> dict[str, Any]:
        return self.client.messages.create(model=self.model, **kwargs).model_dump()


class MockLLM:
    """Deterministic stand-in: reads the runbook, then emits a ticket built from the prompt metadata."""

    model = "mock"

    def __init__(self, package: PromptPackage) -> None:
        self.package, self.calls = package, 0

    def create(self, **kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        p = self.package
        if self.calls == 1:
            block = {"type": "tool_use", "id": "mock-1", "name": TOOL_NAME,
                     "input": {"consulta": "runbook_text", "parametros": [p.metadata["rule_id"]]}}  # fmt: skip
            return {"content": [block], "stop_reason": "tool_use", "usage": {"input_tokens": 0, "output_tokens": 0}}
        ticket = {
            "ticket_id": f"TKT-MOCK-{p.alert_id}", "alert_ids": [p.alert_id],
            "title": f"[MOCK] Triaje simulado de {p.metadata['rule_id']}", "verdict": "needs_more_info",
            "confidence": 0.1, "severity": p.metadata["base_severity"] if p.metadata["base_severity"] in
            ("informational", "low", "medium", "high", "critical") else "low",
            "severity_rationale": "Modo mock: severidad base de la matriz sin ajuste.",
            "summary": "Respuesta simulada sin LLM para probar el flujo y la validación del formato.",
            "evidence": [], "recommended_actions": [{"action": "revisar", "target": "analista", "requires_approval": False}],
            "escalation": {"escalate": False, "to": "", "reason": ""},
            "open_questions": ["Modo mock: no se ha consultado al LLM."],
        }  # fmt: skip
        block = {"type": "tool_use", "id": f"mock-{self.calls}", "name": TICKET_TOOL, "input": ticket}
        return {"content": [block], "stop_reason": "tool_use", "usage": {"input_tokens": 0, "output_tokens": 0}}


@dataclass
class TriageResult:
    alert_id: str
    model: str
    ticket: dict[str, Any] | None
    valid: bool
    errors: list[str]
    attempts: int
    transcript: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    elapsed_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Backend(Protocol):
    def execute(self, consulta: str, parametros: list[str], allowed: list[str] | None = None) -> list[dict]: ...


def _clean_block(block: dict[str, Any]) -> dict[str, Any]:
    """Keep only the fields the Messages API accepts back in an assistant turn."""
    if block["type"] == "text":
        return {"type": "text", "text": block.get("text", "")}
    return {"type": "tool_use", "id": block["id"], "name": block["name"], "input": block.get("input") or {}}


def _add_usage(total: dict[str, int], usage: dict[str, Any] | None) -> None:
    for k, v in (usage or {}).items():
        if isinstance(v, int):
            total[k] = total.get(k, 0) + v


class TriageRunner:
    """Prompt package -> LLM with tools -> validated ticket."""

    def __init__(self, builder: PromptBuilder, backend: Backend, max_turns: int = 12, max_repairs: int = 2) -> None:
        self.builder, self.backend = builder, backend
        self.max_turns, self.max_repairs = max_turns, max_repairs

    def request(self, package: PromptPackage) -> dict[str, Any]:
        """Static part of the Messages API request (system, tools) with prompt caching."""
        ticket_tool = {"name": TICKET_TOOL, "description": "Entrega el ticket de triaje final.",
                       "input_schema": tool_schema(package.response_schema)}  # fmt: skip
        tools = [package.tool, ticket_tool | {"cache_control": {"type": "ephemeral"}}]
        system = [{"type": "text", "text": package.system + FINAL_INSTRUCTION, "cache_control": {"type": "ephemeral"}}]
        return {"system": system, "tools": tools, "max_tokens": 4096}

    def _tool_call(self, block: dict[str, Any], allowed: list[str], log: list[dict[str, Any]]) -> dict[str, Any]:
        args = block.get("input") or {}
        try:
            rows = self.backend.execute(args.get("consulta", ""), list(args.get("parametros") or []), allowed)
            content, error = json.dumps(rows, ensure_ascii=False, default=str)[:RESULT_PREVIEW], False
        except (ValueError, TypeError) as exc:
            content, error = f"Error: {exc}", True
        log.append({"type": "consulta", "input": args, "output": content[:1500], "is_error": error})
        return {"type": "tool_result", "tool_use_id": block["id"], "content": content, "is_error": error}

    def run(
        self, alert_id: str, llm: LLM | None = None, analyst_note: str = "", log: list[dict[str, Any]] | None = None
    ) -> TriageResult:
        """Triage one alert. `llm` defaults to the Anthropic API (ANTHROPIC_API_KEY)."""
        started, package = time.monotonic(), self.builder.build(alert_id)
        model = llm or AnthropicLLM()
        user = package.user + (f"\nIndicación del analista: {analyst_note}" if analyst_note.strip() else "")
        messages: list[dict[str, Any]] = [{"role": "user", "content": user}]
        allowed, req = [q.name for q in package.queries], self.request(package)
        log = [] if log is None else log  # shared list: the UI polls it while the run is in progress
        usage: dict[str, int] = {}
        ticket, errors, attempts = None, ["el modelo no entregó ningún ticket"], 0
        for _ in range(self.max_turns):
            resp = model.create(messages=messages, **req)
            _add_usage(usage, resp.get("usage"))
            content = [_clean_block(b) for b in resp.get("content", []) if b.get("type") in ("text", "tool_use")]
            messages.append({"role": "assistant", "content": content})
            results, done = [], False
            for block in content:
                if block["type"] == "text" and block.get("text", "").strip():
                    log.append({"type": "texto", "output": block["text"][:1500]})
                elif block["type"] == "tool_use" and block["name"] == TICKET_TOOL:
                    attempts += 1
                    ticket, errors = (
                        block.get("input"),
                        validate_ticket(block.get("input"), package.response_schema, alert_id),
                    )
                    log.append({"type": "ticket", "attempt": attempts, "errors": errors})
                    done = not errors or attempts > self.max_repairs
                    msg = "Ticket válido." if not errors else "Ticket no válido, corrige: " + "; ".join(errors)
                    results.append(
                        {"type": "tool_result", "tool_use_id": block["id"], "content": msg, "is_error": bool(errors)}
                    )
                elif block["type"] == "tool_use":
                    results.append(self._tool_call(block, allowed, log))
            if done:
                break
            if not results:
                results = [{"type": "text", "text": "Entrega el resultado llamando a emitir_ticket."}]
            messages.append({"role": "user", "content": results})
        return TriageResult(alert_id, getattr(model, "model", "?"), ticket, not errors, errors, attempts, log, usage,
                            round(time.monotonic() - started, 2))  # fmt: skip
