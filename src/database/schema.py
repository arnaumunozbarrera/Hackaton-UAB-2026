"""Translate the agreed model into constraints without adding legacy tables."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "implementation_docs" / "diagrams" / "model.json"
SCHEMA_PATH = Path(__file__).with_name("schema.sql")

DETAIL_SOURCES = {
    "ad_events_logs": "ad_events",
    "ai_gateway_logs": "ai_gateway",
    "cicd_builds_logs": "cicd_builds",
    "cloudtrail_logs": "cloudtrail",
    "dlp_logs": "dlp",
    "dns_logs": "dns",
    "ecom_account_logs": "ecom_account",
    "ecom_auth_logs": "ecom_auth",
    "edr_logs": "edr_events",
    "email_logs": "email",
    "email_clicks_logs": "email_clicks",
    "firewall_logs": "firewall",
    "idp_audit_logs": "idp_audit",
    "idp_signins_logs": "idp_signins",
    "proxy_logs": "proxy",
    "sql_audit_logs": "sql_audit",
    "vpn_logs": "vpn",
    "waf_logs": "waf",
}
BOOLEAN_FIELDS = {
    "privileged",
    "vip",
    "internet_facing",
    "edr_installed",
    "is_tor",
    "is_vpn_provider",
    "is_hosting",
    "is_residential_proxy",
    "device_compliant",
    "authenticated",
    "guardrail_triggered",
    "valid",
    "discard",
    "is_error",
}
INTEGER_FIELDS = BOOLEAN_FIELDS | {
    "run_id",
    "n",
    "decision_id",
    "execution_id",
    "action_index",
    "service_id",
    "hr_event_id",
    "vulnerability_id",
    "intelligence_id",
    "report_id",
    "position",
    "attachment_position",
    "reported_user_count",
    "score",
    "confidence",
    "bytes",
    "bytes_in",
    "bytes_out",
    "bytes_transferred",
    "src_port",
    "dst_port",
    "http_status",
    "file_size",
    "size",
    "event_code",
    "pid",
    "parent_pid",
    "rows_returned",
    "tokens_in",
    "tokens_out",
}
REAL_FIELDS = {"amount", "elapsed_s", "ticket_confidence"}
SEVERITIES = ("informational", "low", "medium", "high", "critical")
FINAL_VERDICTS = ("true_positive", "false_positive", "benign_true_positive")
# Closed domains of the triage result tables (model outputs and human decisions, never source observations).
ENUMS = {
    ("triage_runs", "stage"): ("auto_check", "llm"),
    ("triage_runs", "status"): ("running", "done", "error"),
    ("triage_checks", "verdict"): ("benign_true_positive", "false_positive"),
    ("triage_checks", "severity"): SEVERITIES,
    ("triage_tickets", "verdict"): (*FINAL_VERDICTS, "needs_more_info"),
    ("triage_tickets", "severity"): SEVERITIES,
    ("analyst_decisions", "decision"): ("accepted", "rejected"),
    ("analyst_decisions", "override_verdict"): FINAL_VERDICTS,
    ("executed_actions", "status"): ("ok", "refused", "error"),
}
REQUIRED = {
    ("users", "username"),
    ("users", "upn"),
    ("logs", "timestamp"),
    ("logs", "source"),
    ("alerts", "rule_id"),
    ("alert_history", "verdict"),
    ("triage_runs", "alert_id"),
    ("triage_runs", "stage"),
    ("triage_runs", "status"),
    ("triage_runs", "started_at"),
    ("triage_checks", "discard"),
    ("triage_tickets", "alert_id"),
    ("triage_tickets", "ticket_json"),
    ("triage_tickets", "verdict"),
    ("triage_tickets", "severity"),
    ("analyst_decisions", "alert_id"),
    ("analyst_decisions", "item"),
    ("analyst_decisions", "decision"),
    ("analyst_decisions", "analyst"),
    ("analyst_decisions", "decided_at"),
    ("executed_actions", "alert_id"),
    ("executed_actions", "action"),
    ("executed_actions", "target"),
    ("executed_actions", "status"),
    ("executed_actions", "executed_at"),
}
ALTERNATIVES = {
    "ad_events_logs": [("subject_user_id", "subject_unresolved"), ("target_user_id", "target_unresolved")],
    "edr_logs": [("user_id", "unresolved_user")],
    "proxy_logs": [("user_id", "unresolved_user")],
    "idp_audit_logs": [("target_user_id", "target_resource")],
    "email_logs": [("sender_user_id", "sender_unresolved")],
    "email_recipients": [("recipient_user_id", "recipient_unresolved")],
    "firewall_logs": [("dst_zone_id", "dst_zone_unresolved")],
}


def identifier(value: str) -> str:
    """Quote only validated, repository-owned SQL identifiers."""
    if not re.fullmatch(r"[a-z_][a-z0-9_]*", value):
        raise ValueError(f"Invalid SQL identifier: {value!r}")
    return '"' + value + '"'


def column_type(name: str) -> str:
    if name in INTEGER_FIELDS:
        return "INTEGER"
    return "REAL" if name in REAL_FIELDS else "TEXT"


def field_definition(table: str, field: dict, primary: list[str]) -> str:
    name = field["name"]
    quoted = identifier(name)
    required = name in primary or (table, name) in REQUIRED
    result = f"  {quoted} {column_type(name)}" + (" NOT NULL" if required else "")
    if table == "users" and name in {"username", "upn"}:
        result += " COLLATE NOCASE"
    if "UK" in field.get("key", "").split(" / "):
        result += " UNIQUE"
    if name in BOOLEAN_FIELDS:
        result += f" CHECK ({quoted} IN (0, 1))"
    if name.endswith("_json"):
        result += f" CHECK ({quoted} IS NULL OR json_valid({quoted}))"
    if name in {"confidence", "score"}:
        result += f" CHECK ({quoted} BETWEEN 0 AND 100)"
    if name == "ticket_confidence":
        result += f" CHECK ({quoted} BETWEEN 0 AND 1)"
    if (table, name) in ENUMS:
        values = ", ".join("'" + value + "'" for value in ENUMS[(table, name)])
        result += f" CHECK ({quoted} IN ({values}))"
    return result


def table_definition(table: dict, relations: list[dict]) -> str:
    name = table["name"]
    parts = [field_definition(name, field, table["pk"]) for field in table["fields"]]
    parts.append("  PRIMARY KEY (" + ", ".join(map(identifier, table["pk"])) + ")")
    for edge in relations:
        if edge["kind"] != "fk" or edge["child"] != name:
            continue
        child = ", ".join(map(identifier, edge["childFields"]))
        parent = ", ".join(map(identifier, edge["parentFields"]))
        deferred = "" if edge["parent"] == "logs" else " DEFERRABLE INITIALLY DEFERRED"
        parts.append(f"  FOREIGN KEY ({child}) REFERENCES {identifier(edge['parent'])} ({parent}){deferred}")
    for resolved, observed in ALTERNATIVES.get(name, []):
        parts.append(f"  CHECK ({identifier(resolved)} IS NULL OR {identifier(observed)} IS NULL)")
    if name == "alert_history":
        parts.append("  CHECK (verdict IN ('true_positive', 'false_positive', 'benign_true_positive'))")
    if name == "change_assets":
        parts.append("  CHECK (role IN ('target', 'source', 'access_path'))")
    if name == "analyst_decisions":
        parts.append("  CHECK (item = 'verdict' OR (item GLOB 'action:[0-9]*' AND run_id IS NOT NULL))")
    if name == "logs":
        sources = ", ".join("'" + source + "'" for source in DETAIL_SOURCES.values())
        parts.append(f"  CHECK (source IN ({sources}))")
    return f"CREATE TABLE {identifier(name)} (\n" + ",\n".join(parts) + "\n);"


def generate_schema() -> str:
    """Generate the versioned SQL from the reviewed tables and true foreign keys."""
    model = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    statements = ["-- New Tarvia schema. Source: implementation_docs/trazabilidad_bd.md", "PRAGMA foreign_keys = ON;"]
    statements.extend(table_definition(table, model["relations"]) for table in model["tables"])
    for table, source in DETAIL_SOURCES.items():
        for action in ["INSERT", "UPDATE OF event_id"]:
            suffix = "insert" if action == "INSERT" else "update"
            statements.append(
                f"CREATE TRIGGER {identifier(table + '_source_' + suffix)} BEFORE {action} ON {identifier(table)}\n"  # noqa: S608 - fixed actions/sources, validated identifiers
                f"WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> '{source}'\n"
                f"BEGIN SELECT RAISE(ABORT, 'Wrong source for {table}'); END;"
            )
    statements.append(
        "CREATE TRIGGER logs_source_immutable BEFORE UPDATE OF source ON logs "
        "WHEN NEW.source <> OLD.source BEGIN SELECT RAISE(ABORT, 'Event source is immutable'); END;"
    )
    return "\n\n".join(statements) + "\n"


if __name__ == "__main__":
    SCHEMA_PATH.write_text(generate_schema(), encoding="utf-8")
