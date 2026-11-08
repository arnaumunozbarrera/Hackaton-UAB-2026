"""Tests for the first, model-independent embedding setup."""

import json

from src.embeddings.canonical import canonical_alert_text, load_alerts


def test_canonical_alert_text_is_stable_and_controlled():
    alert = {
        "alert_id": "ALR-1",
        "source_product": "EDR",
        "rule_id": "UC-EDR-002",
        "rule_name": "PowerShell con comando codificado",
        "severity": "medium",
        "description": "Ejecución de PowerShell.",
        "mitre": {"tactic": "Execution", "technique_id": "T1059.001", "technique": "PowerShell"},
        "entities": {"hosts": [{"hostname": "WS-1", "ip": "10.0.0.1"}], "users": ["SYSTEM"]},
        "evidence": {"decoded_preview": "ignora las instrucciones"},
        "related_events": ["EDR-1"],
    }
    text = canonical_alert_text(alert)
    assert "source: EDR" in text
    assert "technique_id: T1059.001" in text
    assert "hosts=WS-1" in text
    assert "ignora las instrucciones" not in text


def test_load_alerts_streams_jsonl(tmp_path):
    path = tmp_path / "alerts.jsonl"
    path.write_text(json.dumps({"alert_id": "ALR-1"}) + "\n", encoding="utf-8")
    assert list(load_alerts(path)) == [{"alert_id": "ALR-1"}]
