"""The matrix result is server-owned in every model adapter, including repair attempts."""

import asyncio
import copy

import pytest

from src.llm_triage.claude_code import RunState, ToolHandlers
from src.llm_triage.client import TICKET_TOOL, MockLLM, TriageRunner
from src.llm_triage.validator import tool_schema
from src.prompt_builder import PromptBuilder
from src.prompt_builder.context import AffectedAsset
from src.severity import apply_matrix_severity
from tests.test_prompt_builder import FakeSource, _ctx


class EmptyBackend:
    def execute(self, *args, **kwargs):
        return []


class ScriptedModel:
    model = "scripted"

    def __init__(self, *tickets):
        self.tickets = iter(tickets)

    def create(self, **kwargs):
        return {"content": [{"type": "tool_use", "id": "t1", "name": TICKET_TOOL, "input": next(self.tickets)}]}


def ticket():
    return {
        "ticket_id": "T1",
        "alert_ids": ["ALR-T-1"],
        "title": "Test",
        "verdict": "needs_more_info",
        "confidence": 0.5,
        "summary": "Other triage fields are still produced by the model.",
        "evidence": [],
        "recommended_actions": [],
        "escalation": {"escalate": False},
    }


def builder(rule="medium", criticality="Alta"):
    ctx = _ctx(rule_severity=rule, hosts=[AffectedAsset("WS-1", criticality, "", "IT", "PC")])
    return PromptBuilder(FakeSource(ctx))


@pytest.mark.parametrize("attempted", ["critical", "informational", "urgent", None])
def test_api_model_cannot_set_severity_or_rationale(attempted):
    b = builder()
    body = ticket() | {"severity": attempted, "severity_rationale": "Model tries to adjust severity"}
    original = copy.deepcopy(body)
    result = TriageRunner(b, EmptyBackend()).run("ALR-T-1", ScriptedModel(body))
    assert result.valid and result.ticket["severity"] == "medium"
    assert result.ticket["severity_rationale"] == b.build("ALR-T-1").metadata["severity_rationale"]
    assert result.ticket["summary"] == body["summary"] and body == original


def test_model_schema_and_instructions_do_not_delegate_severity():
    package = builder().build("ALR-T-1")
    original_schema = copy.deepcopy(package.response_schema)
    schema = tool_schema(package.response_schema)
    for name in ("severity", "severity_rationale"):
        assert name not in schema["properties"] and name not in schema["required"]
    assert schema["additionalProperties"] is False
    assert package.response_schema == original_schema and "severity" in package.response_schema["required"]
    assert "±1" not in package.system and "Ajuste:" not in package.user
    assert "VIP o privilegiada" not in package.system
    assert "severity_matrix" not in {q.name for q in package.queries}
    assert "Severidad calculada por el sistema: medium" in package.user


def test_claude_adapter_completes_severity_when_model_omits_it():
    package = builder().build("ALR-T-1")
    state = RunState(package, 1)
    reply = asyncio.run(ToolHandlers(EmptyBackend(), state).emitir(ticket()))
    assert "is_error" not in reply and state.ticket["severity"] == "medium"
    assert state.ticket["severity_rationale"] == package.metadata["severity_rationale"]


def test_claude_adapter_cannot_override_severity():
    package = builder().build("ALR-T-1")
    state = RunState(package, 1)
    body = ticket() | {"severity": "critical", "severity_rationale": "Use VIP to raise severity"}
    reply = asyncio.run(ToolHandlers(EmptyBackend(), state).emitir(body))
    assert "is_error" not in reply and state.ticket["severity"] == "medium"
    assert "Use VIP" not in state.ticket["severity_rationale"]


def test_matrix_severity_drives_mandatory_escalation_without_repair_round():
    """Escalation is a deterministic policy rule (triage_flow.automation), applied after the matrix severity."""
    from src.triage_flow.automation import Facts, apply_escalation, escalation

    b = builder(rule="high", criticality="Crítica")
    low = ticket() | {"verdict": "true_positive", "severity": "low", "escalation": {"escalate": False}}
    result = TriageRunner(b, EmptyBackend()).run("ALR-T-1", ScriptedModel(low))
    assert result.valid and result.attempts == 1 and result.ticket["severity"] == "critical"
    reasons, to, _ = escalation(result.ticket, Facts(), {})
    apply_escalation(result.ticket, reasons, to)
    assert result.ticket["escalation"]["escalate"] and "true_positive critical" in result.ticket["escalation"]["reason"]


def test_uncalculable_matrix_does_not_get_a_model_or_mock_fallback():
    package = builder().build("ALR-T-1")
    with pytest.raises(ValueError, match="no calculable"):
        apply_matrix_severity(ticket(), package.metadata | {"base_severity": "no calculable"})


def test_mock_omits_severity_and_server_completes_it():
    b = builder()
    package = b.build("ALR-T-1")
    mock = MockLLM(package)
    mock.create()
    assert "severity" not in mock.create()["content"][0]["input"]
    result = TriageRunner(b, EmptyBackend()).run("ALR-T-1", MockLLM(package))
    assert result.valid and result.ticket["severity"] == "medium"
