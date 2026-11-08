"""Tests for the first, model-independent embedding setup."""

import json

from src.embeddings.canonical import canonical_alert_text, load_alerts
from src.embeddings.log_context import log_context_text, select_log_context
from src.embeddings.vulnerabilities import from_csv
from src.log_noise_discard.stages import LogRecord


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


def test_select_log_context_has_per_alert_budget_and_source_diversity():
    alert = {
        "alert_id": "ALR-1",
        "created_at": "2026-10-05T10:00:00.000Z",
        "source_product": "EDR",
        "rule_id": "UC-EDR-002",
        "entities": {"hosts": [{"hostname": "WS-1"}]},
        "related_events": ["EDR-1"],
        "evidence": {},
    }
    records = [
        LogRecord(
            "EDR-1",
            "edr_events",
            ("process_start", "powershell.exe"),
            "ws-1",
            1,
            {
                "event_id": "EDR-1",
                "timestamp": "2026-10-05T10:01:00.000Z",
                "hostname": "WS-1",
                "event_type": "process_start",
            },
        ),
        LogRecord(
            "EDR-2",
            "edr_events",
            ("process_start", "powershell.exe"),
            "ws-1",
            1,
            {
                "event_id": "EDR-2",
                "timestamp": "2026-10-05T10:02:00.000Z",
                "hostname": "WS-1",
                "event_type": "process_start",
            },
        ),
        LogRecord(
            "DNS-1",
            "dns",
            ("dga.example", "A"),
            "ws-1",
            1,
            {"event_id": "DNS-1", "timestamp": "2026-10-05T10:03:00.000Z", "hostname": "WS-1", "query": "dga.example"},
        ),
        LogRecord(
            "OLD-1",
            "edr_events",
            ("old",),
            "ws-1",
            1,
            {"event_id": "OLD-1", "timestamp": "2026-10-01T10:00:00.000Z", "hostname": "WS-1"},
        ),
    ]
    selected = select_log_context(alert, records, budget=3, per_source=2)
    assert len(selected) == 2
    assert {row.source for row in selected} == {"edr_events", "dns"}
    assert "dga.example" in log_context_text(selected)


def test_known_vulnerabilities_are_added_only_for_affected_hosts(tmp_path):
    inventory = tmp_path / "02_inventario"
    inventory.mkdir()
    (inventory / "vulnerabilidades.csv").write_text(
        "hostname,id,producto,severidad_cvss,estado,detectada,notas\n"
        "WS-1,CVE-2025-49704,Google Chrome,8.1,abierta,2026-01-01,nota interna\n"
        "WS-1,CVE-2021-34527,Print Spooler,8.8,corregida,2021-07-02,parcheado\n",
        encoding="utf-8",
    )
    (inventory / "activos.csv").write_text(
        "asset_id,hostname,criticality,internet_facing\nA1,WS-1,Alta,False\n", encoding="utf-8"
    )
    vulns = from_csv(tmp_path)
    alert = {"alert_id": "ALR-1", "rule_id": "UC-EDR-002", "entities": {"hosts": [{"hostname": "WS-1"}]}}
    text = canonical_alert_text(alert, vulns)
    expected = "known_vulnerabilities: WS-1=CVE-2025-49704 Google Chrome cvss=8.1 criticality=Alta exposure=internal"
    assert expected in text
    assert "CVE-2021-34527" not in text  # fixed vulnerabilities are ignored
    assert "nota interna" not in text  # free-text notes stay out of the vector
    other = {"alert_id": "ALR-2", "rule_id": "UC-EDR-002", "entities": {"hosts": [{"hostname": "WS-2"}]}}
    assert canonical_alert_text(other, vulns) == canonical_alert_text(other)
