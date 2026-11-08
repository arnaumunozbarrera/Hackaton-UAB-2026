"""OpenAI-compatible chat client for a model hosted outside Anthropic.

The triage loop speaks the Anthropic Messages shape (system blocks, tool_use, tool_result). A cluster
server such as vLLM, SGLang, TGI or Ollama usually exposes `/v1/chat/completions` instead. This module
translates one request and one response so `TriageRunner` stays unchanged. `--llm anthropic` and
`--llm claude-code` never read these settings.

    TARVIA_OPENAI_BASE_URL=http://host:8000/v1   # no trailing path; /chat/completions is appended
    TARVIA_OPENAI_MODEL=the-name-the-server-reports
    TARVIA_OPENAI_API_KEY=                        # optional; sent as Authorization: Bearer
    TARVIA_OPENAI_TIMEOUT=300                     # optional, seconds
    TARVIA_OPENAI_MAX_TOKENS=4096                 # optional override of the loop's max_tokens
"""

from __future__ import annotations

import json
import os
from typing import Any

import requests

DEFAULT_TIMEOUT = 300.0


class OpenAICompatibleLLM:
    """`LLM.create` against `{base_url}/chat/completions`, returning Anthropic-shaped dicts."""

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.model = model or os.environ.get("TARVIA_OPENAI_MODEL", "")
        self.base_url = (base_url or os.environ.get("TARVIA_OPENAI_BASE_URL", "")).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("TARVIA_OPENAI_API_KEY", "")
        env_timeout = os.environ.get("TARVIA_OPENAI_TIMEOUT")
        self.timeout = timeout if timeout is not None else float(env_timeout or DEFAULT_TIMEOUT)
        self.session = session or requests.Session()
        if not self.base_url:
            raise RuntimeError("TARVIA_OPENAI_BASE_URL is not set (for example http://host:8000/v1)")
        if not self.model:
            raise RuntimeError("TARVIA_OPENAI_MODEL is not set (the id from the cluster's /v1/models)")

    def create(self, **kwargs: Any) -> dict[str, Any]:
        body = chat_request(
            self.model,
            kwargs["messages"],
            kwargs.get("system") or [],
            kwargs.get("tools") or [],
            int(os.environ.get("TARVIA_OPENAI_MAX_TOKENS") or kwargs.get("max_tokens") or 4096),
        )
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        response = self.session.post(
            f"{self.base_url}/chat/completions", json=body, headers=headers, timeout=self.timeout
        )
        if not response.ok:
            raise RuntimeError(f"cluster model HTTP {response.status_code}: {response.text[:500]}")
        return from_chat_response(response.json())


def chat_request(
    model: str,
    messages: list[dict[str, Any]],
    system: list[dict[str, Any]] | str,
    tools: list[dict[str, Any]],
    max_tokens: int,
) -> dict[str, Any]:
    """One Anthropic-shaped turn as a chat-completions body. `cache_control` is dropped."""
    converted = [{"role": "system", "content": _system_text(system)}]
    for message in messages:
        converted.extend(_convert_message(message))
    body: dict[str, Any] = {"model": model, "messages": converted, "max_tokens": max_tokens}
    if tools:
        body["tools"] = [_openai_tool(tool) for tool in tools]
        body["tool_choice"] = "auto"
    return body


def from_chat_response(payload: dict[str, Any]) -> dict[str, Any]:
    """Chat-completions JSON as the dict `TriageRunner` reads (`content`, `stop_reason`, `usage`)."""
    choice = (payload.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    content: list[dict[str, Any]] = []
    for text in _text_parts(message.get("content")):
        content.append({"type": "text", "text": text})
    for call in message.get("tool_calls") or []:
        function = call.get("function") or {}
        content.append({
            "type": "tool_use", "id": call.get("id") or "call", "name": function.get("name") or "",
            "input": _parse_arguments(function.get("arguments")),
        })  # fmt: skip
    stop = "tool_use" if any(block["type"] == "tool_use" for block in content) else "end_turn"
    if choice.get("finish_reason") == "length":
        stop = "max_tokens"
    usage = payload.get("usage") or {}
    return {
        "content": content,
        "stop_reason": stop,
        "usage": {
            "input_tokens": int(usage.get("prompt_tokens") or 0),
            "output_tokens": int(usage.get("completion_tokens") or 0),
        },
    }


def _system_text(system: list[dict[str, Any]] | str) -> str:
    if isinstance(system, str):
        return system
    return "\n".join(
        block.get("text", "") for block in system if isinstance(block, dict) and block.get("type") == "text"
    )


def _openai_tool(tool: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool["name"],
            "description": tool.get("description", ""),
            "parameters": tool.get("input_schema") or {"type": "object", "properties": {}},
        },
    }


def _convert_message(message: dict[str, Any]) -> list[dict[str, Any]]:
    content = message.get("content")
    if message.get("role") == "assistant":
        return [_assistant(content)]
    if isinstance(content, str):
        return [{"role": "user", "content": content}]
    converted: list[dict[str, Any]] = []
    texts: list[str] = []

    def flush() -> None:
        if texts:
            converted.append({"role": "user", "content": "\n".join(texts)})
            texts.clear()

    for block in content or []:
        if block.get("type") == "tool_result":
            flush()
            converted.append(
                {"role": "tool", "tool_call_id": block["tool_use_id"], "content": str(block.get("content", ""))}
            )
        elif block.get("type") == "text":
            texts.append(block.get("text", ""))
    flush()
    return converted


def _assistant(content: Any) -> dict[str, Any]:
    if isinstance(content, str):
        return {"role": "assistant", "content": content}
    texts, calls = [], []
    for block in content or []:
        if block.get("type") == "text" and block.get("text"):
            texts.append(block["text"])
        elif block.get("type") == "tool_use":
            calls.append({
                "id": block["id"], "type": "function",
                "function": {"name": block["name"], "arguments": json.dumps(block.get("input") or {}, ensure_ascii=False)},
            })  # fmt: skip
    out: dict[str, Any] = {"role": "assistant", "content": "\n".join(texts) or None}
    if calls:
        out["tool_calls"] = calls
    return out


def _text_parts(content: Any) -> list[str]:
    if isinstance(content, str):
        return [content] if content.strip() else []
    parts = []
    for item in content or []:
        if isinstance(item, str) and item.strip():
            parts.append(item)
        elif isinstance(item, dict) and item.get("text", "").strip():
            parts.append(item["text"])
    return parts


def _parse_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"_unparsed": raw}
    return parsed if isinstance(parsed, dict) else {"_unparsed": parsed}
