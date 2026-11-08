"""Cluster model adapter: Anthropic message shape to chat completions and back. No network."""

import json

import pytest

from src.llm_triage.openai_compat import OpenAICompatibleLLM, chat_request, from_chat_response
from src.workflow import LLM_MODES


def test_openai_is_an_extra_mode():
    assert "openai" in LLM_MODES
    assert "anthropic" in LLM_MODES and "claude-code" in LLM_MODES


def test_request_maps_tools_and_tool_results():
    body = chat_request(
        "cluster-model",
        [
            {"role": "user", "content": "alerta"},
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "miro el runbook"},
                    {
                        "type": "tool_use",
                        "id": "call-1",
                        "name": "solicitar_contexto",
                        "input": {"motivo": "falta el runbook"},
                    },
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "call-1", "content": "filas"},
                    {"type": "text", "text": "Entrega el ticket."},
                ],
            },
        ],
        [{"type": "text", "text": "sistema", "cache_control": {"type": "ephemeral"}}],
        [
            {
                "name": "emitir_ticket",
                "description": "entrega",
                "input_schema": {"type": "object"},
                "cache_control": {"type": "ephemeral"},
            }
        ],
        4096,
    )
    assert body["model"] == "cluster-model"
    assert body["messages"][0] == {"role": "system", "content": "sistema"}
    assistant = body["messages"][2]
    assert assistant["tool_calls"][0]["function"]["name"] == "solicitar_contexto"
    assert json.loads(assistant["tool_calls"][0]["function"]["arguments"])["motivo"] == "falta el runbook"
    assert body["messages"][3] == {"role": "tool", "tool_call_id": "call-1", "content": "filas"}
    assert body["messages"][4] == {"role": "user", "content": "Entrega el ticket."}
    assert body["tools"][0]["function"]["name"] == "emitir_ticket"
    assert "cache_control" not in json.dumps(body)


def test_response_becomes_a_tool_use_block():
    parsed = from_chat_response(
        {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "c1",
                                "function": {"name": "emitir_ticket", "arguments": '{"verdict": "false_positive"}'},
                            }
                        ],
                    },
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 4},
        }
    )
    assert parsed["stop_reason"] == "tool_use"
    assert parsed["content"] == [
        {"type": "tool_use", "id": "c1", "name": "emitir_ticket", "input": {"verdict": "false_positive"}}
    ]
    assert parsed["usage"] == {"input_tokens": 10, "output_tokens": 4}


def test_broken_arguments_stay_visible():
    parsed = from_chat_response(
        {
            "choices": [
                {"message": {"tool_calls": [{"id": "c", "function": {"name": "emitir_ticket", "arguments": "{no"}}]}}
            ],
        }
    )
    assert parsed["content"][0]["input"] == {"_unparsed": "{no"}


def test_create_posts_to_the_cluster(monkeypatch):
    captured = {}

    class FakeResponse:
        ok = True

        def json(self):
            return {"choices": [{"message": {"content": "hola"}}], "usage": {}}

    class FakeSession:
        def post(self, url, json, headers, timeout):
            captured.update(url=url, json=json, headers=headers, timeout=timeout)
            return FakeResponse()

    llm = OpenAICompatibleLLM(
        model="m", base_url="http://cluster:8000/v1/", api_key="sekret", timeout=12, session=FakeSession()
    )
    out = llm.create(messages=[{"role": "user", "content": "a"}], system="s", tools=[], max_tokens=100)
    assert captured["url"] == "http://cluster:8000/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer sekret"
    assert captured["json"]["max_tokens"] == 100
    assert captured["timeout"] == 12
    assert out["content"] == [{"type": "text", "text": "hola"}]
    assert out["stop_reason"] == "end_turn"


def test_missing_endpoint_is_reported(monkeypatch):
    monkeypatch.delenv("TARVIA_OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("TARVIA_OPENAI_MODEL", raising=False)
    with pytest.raises(RuntimeError, match="TARVIA_OPENAI_BASE_URL"):
        OpenAICompatibleLLM(model="m", base_url="", api_key="")
