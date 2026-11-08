"""Triage through the local Claude Code CLI (Claude Agent SDK) using your Claude plan login, without an API key.

Why: with a Pro/Max subscription, Claude Code and the Agent SDK signed in with your plan draw from the plan's
usage limits instead of API credits (personal, local use). The SDK spawns the Claude Code CLI; our two tools run
in-process as an SDK MCP server:
- `consultar_bd`: answered by the same backend as the API runner (dataset today, database later);
- `emitir_ticket`: validates the ticket (schema + policy) and returns the errors to the model for correction.
Built-in Claude Code tools are removed (`tools=[]`) and on-disk settings are ignored (`setting_sources=[]`), so the
agent can only read through `consultar_bd`.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

from ..prompt_builder import PromptBuilder, PromptPackage
from ..prompt_builder.tools import TOOL_NAME
from .client import RESULT_PREVIEW, TICKET_TOOL, Backend, TriageResult
from .validator import tool_schema, validate_ticket

SERVER = "soc"
QUALIFIED = {name: f"mcp__{SERVER}__{name}" for name in (TOOL_NAME, TICKET_TOOL)}
INSTRUCTION = (
    f"\nHerramientas: {QUALIFIED[TOOL_NAME]} (consultar_bd) para leer datos y {QUALIFIED[TICKET_TOOL]} "
    "(emitir_ticket) para entregar el ticket completo. Termina en cuanto emitir_ticket confirme que el ticket es válido."
)


def _text(message: str, error: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"content": [{"type": "text", "text": message}]}
    if error:
        result["is_error"] = True
    return result


@dataclass
class RunState:
    """Per-alert state shared by the tool handlers."""

    package: PromptPackage
    max_repairs: int
    ticket: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=lambda: ["el modelo no entregó ningún ticket"])
    attempts: int = 0
    log: list[dict[str, Any]] = field(default_factory=list)


class ToolHandlers:
    """Plain async handlers (testable without the SDK); `ClaudeCodeRunner` wraps them with `@tool`."""

    def __init__(self, backend: Backend, state: RunState) -> None:
        self.backend, self.state = backend, state

    async def consultar(self, args: dict[str, Any]) -> dict[str, Any]:
        allowed = [q.name for q in self.state.package.queries]
        params = args.get("parametros") or []
        if isinstance(params, str):  # some clients send the array JSON-encoded
            params = json.loads(params) if params.strip().startswith("[") else [params]
        try:
            rows = self.backend.execute(str(args.get("consulta", "")), [str(p) for p in params], allowed)
            content, error = json.dumps(rows, ensure_ascii=False, default=str)[:RESULT_PREVIEW], False
        except (ValueError, TypeError) as exc:
            content, error = f"Error: {exc}", True
        self.state.log.append({"type": "consulta", "input": args, "output": content[:1500], "is_error": error})
        return _text(content, error)

    async def emitir(self, args: dict[str, Any]) -> dict[str, Any]:
        s = self.state
        s.attempts += 1
        s.ticket, s.errors = args, validate_ticket(args, s.package.response_schema, s.package.alert_id)
        s.log.append({"type": "ticket", "attempt": s.attempts, "errors": s.errors})
        if not s.errors:
            return _text("Ticket válido. Termina sin añadir nada más.")
        if s.attempts > s.max_repairs:
            return _text("Ticket no válido y sin más intentos. Termina.", error=True)
        return _text("Ticket no válido, corrige y vuelve a llamar a emitir_ticket: " + "; ".join(s.errors), error=True)


class ClaudeCodeRunner:
    """Same contract as TriageRunner.run, executed by the local Claude Code CLI with the plan login."""

    model_label = "claude-code (suscripción)"

    def __init__(
        self,
        builder: PromptBuilder,
        backend: Backend,
        model: str | None = None,
        max_turns: int = 16,
        max_repairs: int = 2,
    ) -> None:
        self.builder, self.backend, self.model = builder, backend, model
        self.max_turns, self.max_repairs = max_turns, max_repairs

    @staticmethod
    def ensure_subscription_auth() -> bool:
        """Remove ANTHROPIC_API_KEY from this process: with it set, Claude Code bills the API instead of the plan."""
        return os.environ.pop("ANTHROPIC_API_KEY", None) is not None

    def _options(self, package: PromptPackage, handlers: ToolHandlers) -> Any:
        from claude_agent_sdk import ClaudeAgentOptions, create_sdk_mcp_server, tool

        consultar = tool(TOOL_NAME, package.tool["description"], package.tool["input_schema"])(handlers.consultar)
        emitir = tool(TICKET_TOOL, "Entrega el ticket de triaje final.", tool_schema(package.response_schema))(
            handlers.emitir
        )
        return ClaudeAgentOptions(
            system_prompt=package.system + INSTRUCTION,
            tools=[],  # no built-in Claude Code tools (no Bash, Read, Web...)
            mcp_servers={SERVER: create_sdk_mcp_server(name=SERVER, tools=[consultar, emitir])},
            allowed_tools=list(QUALIFIED.values()),
            setting_sources=[],  # ignore CLAUDE.md and user/project settings
            max_turns=self.max_turns,
            model=self.model,
        )

    async def _run(self, package: PromptPackage, prompt: str, state: RunState) -> dict[str, Any]:
        from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock, query

        info: dict[str, Any] = {}
        async for message in query(prompt=prompt, options=self._options(package, ToolHandlers(self.backend, state))):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock) and block.text.strip():
                        state.log.append({"type": "texto", "output": block.text[:1500]})
            elif isinstance(message, ResultMessage):
                usage = {k: v for k, v in (message.usage or {}).items() if isinstance(v, int)}
                info = {"usage": usage | {"num_turns": message.num_turns}, "subtype": message.subtype,
                        "cost_estimate_usd": message.total_cost_usd}  # fmt: skip
        return info

    def run(
        self, alert_id: str, llm: Any = None, analyst_note: str = "", log: list[dict[str, Any]] | None = None
    ) -> TriageResult:
        """Triage one alert through Claude Code. `llm` is ignored (kept for interface compatibility)."""
        started, package = time.monotonic(), self.builder.build(alert_id)
        self.ensure_subscription_auth()
        state = RunState(package, self.max_repairs, log=[] if log is None else log)
        prompt = package.user + (f"\nIndicación del analista: {analyst_note}" if analyst_note.strip() else "")
        info = asyncio.run(self._run(package, prompt, state))
        usage = dict(info.get("usage", {}))
        if info.get("subtype") not in (None, "success"):
            state.log.append({"type": "fin", "output": f"Claude Code terminó con {info['subtype']}"})
        return TriageResult(alert_id, self.model or self.model_label, state.ticket, not state.errors, state.errors,
                            state.attempts, state.log, usage, round(time.monotonic() - started, 2))  # fmt: skip
