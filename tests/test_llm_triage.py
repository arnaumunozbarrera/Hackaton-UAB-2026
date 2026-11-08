"""Tests for src.llm_triage: ticket validation, dataset backend and the tool loop with fake models (no network)."""

import copy
import json
from pathlib import Path

import pytest

DOCS = Path("docs")
pytestmark = pytest.mark.skipif(not (DOCS / "03_alertas" / "alertas.jsonl").exists(), reason="dataset docs/ missing")

from src.llm_triage import DatasetToolBackend, MockLLM, TriageRunner, validate_ticket  # noqa: E402
from src.llm_triage.client import TICKET_TOOL  # noqa: E402
from src.prompt_builder import DatasetContextSource, PromptBuilder  # noqa: E402

ALERT = "ALR-20261005-000172"  # WAF, cites WAF-0001840


@pytest.fixture(scope="module")
def stack():
    source = DatasetContextSource(DOCS)
    builder = PromptBuilder(source)
    return builder, DatasetToolBackend(source, builder)


@pytest.fixture()
def ticket():
    data = json.loads((DOCS / "01_contexto" / "ticket_ejemplo.json").read_text(encoding="utf-8"))
    data["alert_ids"] = [ALERT]
    return data


def schema():
    return json.loads((DOCS / "01_contexto" / "ticket_salida.schema.json").read_text(encoding="utf-8"))


def test_example_ticket_is_valid(ticket):
    assert validate_ticket(ticket, schema(), ALERT) == []


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda t: t.pop("summary"), "summary"),
        (lambda t: t.update(severity="urgent"), "severity"),
        (lambda t: t.update(alert_ids=["ALR-OTRA"]), "alert_ids debe incluir"),
        (lambda t: t.update(executed_actions=[{"action": "isolate_host"}]), "executed_actions"),
        (
            lambda t: t["recommended_actions"].append(
                {"action": "aislar equipo", "target": "WS-1", "requires_approval": False}
            ),
            "requiere aprobación",
        ),
        (lambda t: t.update(verdict="true_positive", severity="high"), "escalation.escalate"),
    ],
)
def test_invalid_tickets_are_rejected(ticket, mutate, expected):
    bad = copy.deepcopy(ticket)
    mutate(bad)
    assert any(expected in e for e in validate_ticket(bad, schema(), ALERT))


def test_backend_answers_catalogue_functions(stack):
    _, backend = stack
    rb = backend.execute("runbook_text", ["UC-WEB-001"])[0]
    assert rb["runbook"] == "RB-05" and rb["runbook_checks"].startswith("1.")
    detail = backend.execute("log_detail", ["WAF-0001840"])[0]
    assert detail["source"] == "waf" and "WAF-0001840" in detail["detail"]
    events = backend.execute("alert_events", [ALERT])
    assert events[0]["estado"] == "apartado N4"
    assert backend.execute("indicator", ["198.18.11.49"])[0]["as_org"].startswith("Hosting")
    assert backend.execute("severity_matrix", ["low"])[-1] == {"criticality": "Crítica", "base_severity": "medium"}


def test_backend_activity_scan_and_validation(stack):
    _, backend = stack
    rows = backend.execute("ip_activity", ["198.18.11.49", "2026-10-03T22:13:15.000Z", "2026-10-05T22:13:15.000Z"])
    assert rows and all(r["src_ip"] == "198.18.11.49" for r in rows)
    with pytest.raises(ValueError):
        backend.execute("log_detail", [])
    with pytest.raises(ValueError):
        backend.execute("user_profile", ["x"], allowed=["log_detail"])


def test_request_uses_cache_and_ticket_tool(stack):
    builder, backend = stack
    req = TriageRunner(builder, backend).request(builder.build(ALERT))
    assert req["system"][0]["cache_control"] == {"type": "ephemeral"}
    names = [t["name"] for t in req["tools"]]
    assert names == ["consultar_bd", TICKET_TOOL] and "$schema" not in req["tools"][1]["input_schema"]


def test_mock_run_is_valid(stack):
    builder, backend = stack
    result = TriageRunner(builder, backend).run(ALERT, MockLLM(builder.build(ALERT)))
    assert result.valid and result.attempts == 1
    assert [s["type"] for s in result.transcript] == ["consulta", "ticket"]


class ScriptedLLM:
    """Returns the given responses in order (each a list of content blocks)."""

    model = "scripted"

    def __init__(self, *turns):
        self.turns, self.seen = list(turns), []

    def create(self, **kwargs):
        self.seen.append(copy.deepcopy(kwargs["messages"]))
        content = self.turns.pop(0)
        return {"content": content, "stop_reason": "tool_use", "usage": {"input_tokens": 10, "output_tokens": 5}}


def _ticket_block(i, ticket):
    return [{"type": "tool_use", "id": f"t{i}", "name": TICKET_TOOL, "input": ticket}]


def test_invalid_ticket_is_sent_back_and_repaired(stack, ticket):
    builder, backend = stack
    bad = copy.deepcopy(ticket)
    bad.pop("summary")
    llm = ScriptedLLM(
        [
            {
                "type": "tool_use",
                "id": "q1",
                "name": "consultar_bd",
                "input": {"consulta": "no_existe", "parametros": []},
            }
        ],
        _ticket_block(2, bad),
        _ticket_block(3, ticket),
    )
    result = TriageRunner(builder, backend).run(ALERT, llm)
    assert result.valid and result.attempts == 2 and result.usage["input_tokens"] == 30
    assert result.transcript[0]["is_error"]  # unknown query reported to the model as a tool error
    last_feedback = llm.seen[-1][-1]["content"][0]
    assert last_feedback["is_error"] and "summary" in last_feedback["content"]


def test_gives_up_after_max_repairs(stack, ticket):
    builder, backend = stack
    bad = copy.deepcopy(ticket)
    bad["severity"] = "urgent"
    llm = ScriptedLLM(*[_ticket_block(i, bad) for i in range(5)])
    result = TriageRunner(builder, backend, max_repairs=2).run(ALERT, llm)
    assert not result.valid and result.attempts == 3 and result.errors


# ---------------------------------------------------------------- Claude Code (subscription) adapter
def test_claude_code_handlers_validate_and_report(stack, ticket):
    import asyncio

    from src.llm_triage.claude_code import RunState, ToolHandlers

    builder, backend = stack
    state = RunState(builder.build(ALERT), max_repairs=1)
    h = ToolHandlers(backend, state)
    ok = asyncio.run(h.consultar({"consulta": "runbook_text", "parametros": ["UC-WEB-001"]}))
    assert "RB-05" in ok["content"][0]["text"] and "is_error" not in ok
    bad_query = asyncio.run(h.consultar({"consulta": "no_existe", "parametros": []}))
    assert bad_query["is_error"]
    bad = copy.deepcopy(ticket)
    bad.pop("summary")
    first = asyncio.run(h.emitir(bad))
    assert first["is_error"] and "corrige" in first["content"][0]["text"]
    good = asyncio.run(h.emitir(ticket))
    assert "is_error" not in good and state.ticket == ticket and state.errors == [] and state.attempts == 2


def test_claude_code_options_restrict_tools(stack, monkeypatch):
    pytest.importorskip("claude_agent_sdk")
    from src.llm_triage.claude_code import QUALIFIED, ClaudeCodeRunner, RunState, ToolHandlers

    builder, backend = stack
    runner = ClaudeCodeRunner(builder, backend, model="sonnet")
    package = builder.build(ALERT)
    opts = runner._options(package, ToolHandlers(backend, RunState(package, 2)))
    assert opts.tools == [] and opts.setting_sources == [] and sorted(opts.allowed_tools) == sorted(QUALIFIED.values())
    assert "soc" in opts.mcp_servers and opts.model == "sonnet"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert ClaudeCodeRunner.ensure_subscription_auth() and "ANTHROPIC_API_KEY" not in __import__("os").environ


def test_background_job_survives_without_holding_the_request():
    import time

    from src.llm_triage.server import App

    app = App("docs", mode="mock")
    job_id = app.start_job(ALERT)
    for _ in range(300):
        job = app.job(job_id)
        if job["status"] != "running":
            break
        time.sleep(0.1)
    assert job["status"] == "done" and job["result"]["valid"]
    assert [s["type"] for s in job["transcript"]] == ["consulta", "ticket"]
    with pytest.raises(KeyError):
        app.start_job("ALR-NO-EXISTE")
