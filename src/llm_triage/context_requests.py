"""Response type 2: read-only context expansion requested by the LLM, always with an explicit reason.

Why: when the identification in the prompt is not enough for a verdict, the model must ask for more data instead
of guessing, and the analyst must see that this happened and why. Each request carries a reason (and optionally
the runbook check it serves), runs at most MAX_QUERIES_PER_REQUEST catalogue queries through the read-only
backend, and is limited per alert so the model eventually delivers a ticket (needs_more_info if data is missing).
Shared by the API runner and the Claude Code runner.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from ..prompt_builder.tools import MAX_QUERIES_PER_REQUEST, MIN_REASON_CHARS

CONTENT_LIMIT = 12000


class Backend(Protocol):
    def execute(self, consulta: str, parametros: list[str], allowed: list[str] | None = None) -> list[dict]: ...


@dataclass
class ContextBudget:
    max_requests: int = 6
    used: int = 0


def _as_list(value: Any) -> Any:
    """Accept arrays sent JSON-encoded as strings by some clients."""
    if isinstance(value, str) and value.strip().startswith("["):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _reject(entry: dict[str, Any], message: str) -> tuple[str, bool, dict[str, Any]]:
    entry.update(is_error=True, output=message)
    return message, True, entry


def handle_context_request(
    args: dict[str, Any], backend: Backend, allowed: list[str], budget: ContextBudget
) -> tuple[str, bool, dict[str, Any]]:
    """Run one type-2 response. Returns (tool result text, is_error, transcript entry for the UI)."""
    reason, check = str(args.get("motivo") or "").strip(), str(args.get("comprobacion") or "").strip()
    queries = _as_list(args.get("consultas"))
    entry: dict[str, Any] = {"type": "contexto", "n": budget.used + 1, "motivo": reason, "comprobacion": check,
                             "consultas": [], "is_error": False}  # fmt: skip
    if len(reason) < MIN_REASON_CHARS:
        return _reject(entry, "Indica el motivo: qué información te falta para decidir y por qué la necesitas.")
    if not isinstance(queries, list) or not 1 <= len(queries) <= MAX_QUERIES_PER_REQUEST:
        return _reject(entry, f"Pide entre 1 y {MAX_QUERIES_PER_REQUEST} consultas por petición.")
    if budget.used >= budget.max_requests:
        return _reject(entry, f"Límite de {budget.max_requests} ampliaciones de contexto alcanzado. Entrega el ticket "
                       "con lo que tienes; si falta información usa needs_more_info y open_questions.")  # fmt: skip
    budget.used += 1
    results = []
    for q in queries:
        q = q if isinstance(q, dict) else {}
        name, params = str(q.get("consulta", "")), [str(p) for p in (_as_list(q.get("parametros")) or [])]
        try:
            rows = backend.execute(name, params, allowed)
            results.append({"consulta": name, "parametros": params, "filas": len(rows), "resultado": rows})
            entry["consultas"].append({"consulta": name, "parametros": params, "filas": len(rows)})
        except (ValueError, TypeError) as exc:
            results.append({"consulta": name, "parametros": params, "error": str(exc)})
            entry["consultas"].append({"consulta": name, "parametros": params, "error": str(exc)})
    content = json.dumps(results, ensure_ascii=False, default=str)[:CONTENT_LIMIT]
    entry["output"] = content[:1500]
    return content, False, entry
