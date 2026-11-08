"""Replace the alert entity JSON with the reviewed relations, preserving evidence."""

import ipaddress
import re

from .core import Directory, Sources, Writer, fields, timestamp

ALERT_FIELDS = {
    "alert_id",
    "created_at",
    "source_product",
    "rule_id",
    "rule_name",
    "severity",
    "status",
    "mitre",
    "description",
    "entities",
    "evidence",
    "related_events",
    "runbook",
}
ENTITY_FIELDS = {"users", "hosts", "ips", "domains", "urls", "files", "processes", "customers", "cloud", "ai_session"}


def check_rule(source: dict, rules: dict[str, dict]) -> None:
    rule = rules[source["rule_id"]]
    for original, column in [("rule_name", "name"), ("source_product", "source_product"), ("runbook", "runbook_id")]:
        if source[original] != rule[column]:
            raise ValueError(f"Alert {original} differs from its rule; cannot discard the original value")
    fields(source["mitre"], {"tactic", "technique_id", "technique"}, "alert mitre")
    for original, column in [("tactic", "tactic"), ("technique_id", "technique_id"), ("technique", "technique_name")]:
        if source["mitre"][original] != rule[column]:
            raise ValueError("Alert MITRE differs from its rule; additional source context would be needed")


def users_and_assets(writer: Writer, alert: str, entities: dict, directory: Directory) -> int | None:
    count = None
    for user in entities.get("users", []):
        fields(user, {"upn", "display_name"}, "alert users")
        aggregate = re.fullmatch(r"\((\d+) cuentas\)", user["upn"])
        if aggregate:
            if count is not None or len(user) != 1:
                raise ValueError("Multiple or annotated aggregate user groups need explicit representation")
            count = int(aggregate[1])
            continue
        user_id = directory.require_user(user["upn"])
        if "display_name" in user and user["display_name"] != directory.user_rows[user_id]["display_name"]:
            raise ValueError("Observed user name differs from inventory")
        writer.add("alert_users", {"alert_id": alert, "user_id": user_id})
    for host in entities.get("hosts", []):
        fields(host, {"hostname", "ip"}, "alert hosts")
        asset_id = directory.asset(host["hostname"])
        if "ip" in host and host["ip"] != directory.asset_rows[asset_id]["ip"]:
            raise ValueError("Observed asset IP differs from inventory")
        writer.add("alert_assets", {"alert_id": alert, "asset_id": asset_id})
    return count


def indicator_values(kind: str, observed: str) -> list[str]:
    if kind != "ip":
        return [observed]
    match = re.fullmatch(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", observed)
    if match and not 0 <= int(match[2]) <= int(match[3]) <= 255:
        raise ValueError("Invalid or reversed IPv4 range")
    values = [match[1] + str(number) for number in range(int(match[2]), int(match[3]) + 1)] if match else [observed]
    if not values:
        raise ValueError("Reversed IP range")
    for value in values:
        ipaddress.ip_address(value)
    return values


def list_entities(writer: Writer, alert: str, entities: dict) -> None:
    mappings = {
        "files": ("alert_files", {"name": "file_name", "sha256": "sha256", "path": "path"}),
        "processes": (
            "alert_processes",
            {"name": "name", "parent": "parent_name", "command_line": "command_line", "pid": "pid"},
        ),
        "customers": ("alert_customers", {"customer_id": "customer_id", "role": "role"}),
    }
    for block, (table, mapping) in mappings.items():
        for position, item in enumerate(entities.get(block, [])):
            fields(item, set(mapping), "alert " + block)
            writer.add(
                table,
                {
                    "alert_id": alert,
                    "position": position,
                    **{target: item.get(original) for original, target in mapping.items()},
                },
            )
    for block, kind in [("ips", "ip"), ("domains", "domain"), ("urls", "url")]:
        for observed in entities.get(block, []):
            for value in indicator_values(kind, observed):
                writer.add("alert_indicators", {"alert_id": alert, "indicator_type": kind, "value": value})


def load_alerts(writer: Writer, sources: Sources, directory: Directory, rules: dict[str, dict]) -> None:
    for source in sources.records("03_alertas/alertas.jsonl"):
        fields(source, ALERT_FIELDS, "alertas.jsonl")
        check_rule(source, rules)
        alert = source["alert_id"]
        entities = source["entities"]
        fields(entities, ENTITY_FIELDS, "alert entities")
        count = users_and_assets(writer, alert, entities, directory)
        list_entities(writer, alert, entities)
        if "cloud" in entities:
            cloud = entities["cloud"]
            fields(cloud, {"account", "identity", "bucket", "access_key", "new_user"}, "alert cloud")
            writer.add(
                "alert_cloud",
                {
                    "alert_id": alert,
                    **{("cloud_account" if key == "account" else key): value for key, value in cloud.items()},
                },
            )
        if "ai_session" in entities:
            writer.add("alert_ai_sessions", {"alert_id": alert, "session_id": entities["ai_session"]})
        for position, event in enumerate(source["related_events"]):
            writer.add("alert_events", {"alert_id": alert, "position": position, "event_id": event})
        writer.add(
            "alerts",
            {
                "alert_id": alert,
                "created_at": timestamp(source["created_at"]),
                "rule_id": source["rule_id"],
                "severity": source["severity"],
                "status": source["status"],
                "description": source["description"],
                "evidence_json": source["evidence"],
                "reported_user_count": count,
            },
        )
