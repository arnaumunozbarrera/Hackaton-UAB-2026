"""Load each log source into its own detail table and preserve unresolved values."""

from collections.abc import Callable
from dataclasses import dataclass, field

from .core import Directory, Sources, Writer, fields, timestamp


def direct(names: str, **renamed: str) -> dict[str, str]:
    return {**{name: name for name in names.split()}, **renamed}


@dataclass(frozen=True)
class LogSpec:
    table: str
    direct: dict[str, str]
    users: tuple[tuple[str, str, str | None], ...] = ()
    assets: dict[str, str] = field(default_factory=dict)
    nested: dict[str, dict[str, str]] = field(default_factory=dict)
    special: tuple[str, ...] = ()

    def covered(self) -> set[str]:
        return {
            "event_id",
            "timestamp",
            *self.direct,
            *self.assets,
            *self.nested,
            *self.special,
            *(source for source, target, fallback in self.users),
        }


SPECS = {
    "ad_events": LogSpec(
        "ad_events_logs",
        direct("event_code", event="event_description", details="details_json"),
        (("subject", "subject_user_id", "subject_unresolved"), ("target", "target_user_id", "target_unresolved")),
        {"dc": "dc_asset_id", "src_host": "source_asset_id"},
    ),
    "ai_gateway": LogSpec(
        "ai_gateway_logs",
        direct("session_id customer_id authenticated src_ip prompt response_summary model tokens_in tokens_out"),
        nested={
            "guardrail": {
                "triggered": "guardrail_triggered",
                "category": "guardrail_category",
                "action": "guardrail_action",
            }
        },
        special=("tool_calls",),
    ),
    "cicd_builds": LogSpec(
        "cicd_builds_logs",
        direct("pipeline build_id step status", details="details_json"),
        assets={"runner": "runner_asset_id"},
    ),
    "cloudtrail": LogSpec(
        "cloudtrail_logs",
        direct(
            "bytes_transferred",
            eventName="event_name",
            eventSource="event_source",
            awsRegion="aws_region",
            sourceIPAddress="src_ip",
            userAgent="user_agent",
            requestParameters="request_parameters_json",
            errorCode="error_code",
        ),
        nested={"userIdentity": {"type": "identity_type", "userName": "identity_name", "accessKeyId": "access_key_id"}},
    ),
    "dlp": LogSpec(
        "dlp_logs",
        direct("channel destination file_name file_size policy action", matches="matches_json"),
        (("user", "user_id", None),),
        {"hostname": "asset_id"},
    ),
    "dns": LogSpec("dns_logs", direct("src_ip query qtype response rcode"), assets={"hostname": "asset_id"}),
    "ecom_account": LogSpec(
        "ecom_account_logs", direct("customer_id src_ip amount", event="event_type", details="details_json")
    ),
    "ecom_auth": LogSpec(
        "ecom_auth_logs", direct("customer_id email src_ip result failure_reason user_agent device_fp captcha")
    ),
    "edr_events": LogSpec(
        "edr_logs",
        direct(
            "event_type process_name process_path command_line parent_name pid parent_pid sha256 signer integrity",
            details="details_json",
        ),
        (("user", "user_id", "unresolved_user"),),
        {"hostname": "asset_id"},
    ),
    "email": LogSpec(
        "email_logs",
        direct("direction message_id subject verdict action spf dkim dmarc sender_ip body_excerpt"),
        (("sender", "sender_user_id", "sender_unresolved"),),
        special=("recipients", "attachments", "urls"),
    ),
    "email_clicks": LogSpec(
        "email_clicks_logs",
        direct("url action verdict_at_click src_ip"),
        (("user", "user_id", None),),
        special=("message_id",),
    ),
    "firewall": LogSpec(
        "firewall_logs",
        direct("src_ip src_port dst_ip dst_port proto action bytes", rule="firewall_rule"),
        special=("zone_src", "zone_dst"),
    ),
    "idp_audit": LogSpec(
        "idp_audit_logs",
        direct("operation src_ip", details="details_json"),
        (("actor_upn", "actor_user_id", None), ("target", "target_user_id", "target_resource")),
    ),
    "idp_signins": LogSpec(
        "idp_signins_logs",
        direct(
            "app result failure_reason mfa_method mfa_result src_ip country city asn user_agent device_id device_compliant session_id risk_level conditional_access"
        ),
        (("user_upn", "user_id", None),),
    ),
    "proxy": LogSpec(
        "proxy_logs",
        direct("src_ip method url domain dst_ip bytes_out bytes_in category action user_agent", status="http_status"),
        (("user", "user_id", "unresolved_user"),),
        {"hostname": "asset_id"},
    ),
    "sql_audit": LogSpec(
        "sql_audit_logs",
        direct("database statement_type object rows_returned statement"),
        (("user", "user_id", None),),
        {"client_host": "client_asset_id"},
    ),
    "vpn": LogSpec(
        "vpn_logs", direct("src_ip assigned_ip action country bytes mfa_result"), (("user", "user_id", None),)
    ),
    "waf": LogSpec(
        "waf_logs",
        direct(
            "src_ip country method host uri action user_agent bytes",
            status="http_status",
            rule_id="waf_rule_id",
            rule_msg="waf_rule_message",
        ),
    ),
}


def email_lists(writer: Writer, row: dict, directory: Directory) -> None:
    event = row["event_id"]
    for position, address in enumerate(row["recipients"]):
        writer.add(
            "email_recipients",
            {
                "event_id": event,
                "position": position,
                **directory.observed_user(address, "recipient_user_id", "recipient_unresolved"),
            },
        )
    for position, item in enumerate(row["attachments"]):
        fields(item, {"name", "sha256", "size", "contains"}, "email attachments")
        writer.add(
            "email_attachments",
            {
                "event_id": event,
                "position": position,
                "file_name": item["name"],
                "sha256": item["sha256"],
                "size": item["size"],
            },
        )
        for inner_position, content in enumerate(item.get("contains", [])):
            fields(content, {"name", "sha256"}, "email attachments.contains")
            writer.add(
                "email_attachment_contents",
                {
                    "event_id": event,
                    "attachment_position": position,
                    "position": inner_position,
                    "file_name": content["name"],
                    "sha256": content["sha256"],
                },
            )
    for position, url in enumerate(row["urls"]):
        writer.add("email_urls", {"event_id": event, "position": position, "url": url})


def special_values(source: str, row: dict, directory: Directory) -> dict:
    if source == "email":
        if row["message_id"] in directory.messages:
            raise ValueError("Duplicate email message_id")
        directory.messages[row["message_id"]] = row["event_id"]
    if source == "email_clicks":
        return {"email_event_id": directory.messages[row["message_id"]]}
    if source != "firewall":
        return {}
    origin, target = row["zone_src"], row["zone_dst"]
    if origin not in directory.zones:
        raise ValueError("Unknown firewall origin zone needs a fallback field")
    return {
        "src_zone_id": origin,
        "dst_zone_id": target if target in directory.zones else None,
        "dst_zone_unresolved": target if target not in directory.zones else None,
    }


def transform(row: dict, source: str, directory: Directory) -> dict:
    spec = SPECS[source]
    fields(row, spec.covered(), source)
    result = {target: row.get(original) for original, target in spec.direct.items()}
    result["event_id"] = row["event_id"]
    for original, target, fallback in spec.users:
        result.update(directory.observed_user(row.get(original), target, fallback))
    for original, target in spec.assets.items():
        result[target] = directory.asset(row.get(original))
    for original, mapping in spec.nested.items():
        block = row[original]
        fields(block, set(mapping), source + "." + original)
        result.update({target: block.get(key) for key, target in mapping.items()})
    result.update(special_values(source, row, directory))
    return result


def load_one(writer: Writer, source: str, row: dict, directory: Directory) -> None:
    result = transform(row, source, directory)
    writer.add("logs", {"event_id": row["event_id"], "timestamp": timestamp(row["timestamp"]), "source": source})
    writer.add(SPECS[source].table, result)
    if source == "email":
        email_lists(writer, row, directory)
    elif source == "ai_gateway":
        for position, call in enumerate(row["tool_calls"]):
            fields(call, {"name", "args", "result"}, "ai_gateway.tool_calls")
            writer.add(
                "ai_tool_calls",
                {
                    "event_id": row["event_id"],
                    "position": position,
                    "name": call["name"],
                    "arguments_json": call["args"],
                    "result": call["result"],
                },
            )


def load_logs(writer: Writer, sources: Sources, directory: Directory, progress: Callable[[str], None]) -> None:
    for source in SPECS:
        extension = ".csv" if source in {"dns", "proxy", "firewall"} else ".jsonl"
        for number, row in enumerate(sources.records("04_logs/" + source + extension), 1):
            try:
                load_one(writer, source, row, directory)
            except (ValueError, KeyError, TypeError) as error:
                raise ValueError(f"Cannot represent {source}, record {number}: {error}") from error
        writer.flush_all()
        writer.connection.commit()
        progress(f"{source}: {writer.counts[SPECS[source].table]:,} events")
