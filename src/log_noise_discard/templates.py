"""Per-source log templates and entities.

Why: two log events with the same template describe the same activity once the per-event volatile fields
(event_id, timestamp, pid, ports, bytes, session ids) are removed. Every noise stage compares templates, so
the definitions live in one place and are shared by all stages.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

Event = Mapping[str, Any]

_NUM = re.compile(r"\d+")
_HEX = re.compile(r"[0-9a-f]{6,}")
_UA_FAMILIES = (
    "BAV2ROPC",
    "python",
    "curl",
    "Boto3",
    "sqlmap",
    "Nikto",
    "Go-http",
    "iPhone",
    "Android",
    "Edg/",
    "Chrome",
    "Firefox",
    "Safari",
    "Outlook",
)


def uri_template(uri: str) -> str:
    """Path of a URI with numbers and hex identifiers replaced by placeholders."""
    path = urlparse(uri).path if uri.startswith("http") else uri.split("?")[0]
    return _HEX.sub("<h>", _NUM.sub("<n>", path))


def ua_family(user_agent: str | None) -> str:
    """Coarse user-agent family (client type), stable across versions."""
    ua = user_agent or ""
    for family in _UA_FAMILIES:
        if family.lower() in ua.lower():
            return family
    return ua[:20]


def _mail_domain(address: str | None) -> str:
    return address.split("@")[-1] if address else ""


def _details(e: Event) -> Mapping[str, Any]:
    d = e.get("details")
    return d if isinstance(d, Mapping) else {}


@dataclass(frozen=True)
class SourceSpec:
    """How to read one log source and reduce its events to (template, entity)."""

    file: str
    fmt: str  # "csv" or "jsonl"
    template: Callable[[Event], tuple]
    entity: Callable[[Event], Any]


SOURCES: dict[str, SourceSpec] = {
    "proxy": SourceSpec(
        "proxy.csv",
        "csv",
        lambda e: (e["domain"], e["method"], e["category"], e["action"], e["status"][:1]),
        lambda e: e["hostname"],
    ),
    "dns": SourceSpec(
        "dns.csv", "csv", lambda e: (e["query"].lower(), e["qtype"], e["rcode"]), lambda e: e["hostname"]
    ),
    "firewall": SourceSpec(
        "firewall.csv",
        "csv",
        lambda e: (e["zone_src"], e["zone_dst"], e["dst_port"], e["proto"], e["action"], e["rule"]),
        lambda e: e["src_ip"],
    ),
    "edr_events": SourceSpec(
        "edr_events.jsonl",
        "jsonl",
        lambda e: (
            e.get("event_type"),
            (e.get("process_name") or "").lower(),
            (e.get("parent_name") or "").lower(),
            e.get("signer"),
            e.get("integrity"),
        ),
        lambda e: e.get("hostname"),
    ),
    "idp_signins": SourceSpec(
        "idp_signins.jsonl",
        "jsonl",
        lambda e: (
            e["app"],
            e["result"],
            e["failure_reason"],
            e["mfa_method"],
            e["mfa_result"],
            e["country"],
            ua_family(e["user_agent"]),
            e["conditional_access"],
            e["risk_level"],
        ),
        lambda e: e["user_upn"],
    ),
    "waf": SourceSpec(
        "waf.jsonl",
        "jsonl",
        lambda e: (e["host"], e["method"], uri_template(e["uri"]), str(e["status"])[:1], e["rule_id"], e["action"]),
        lambda e: e["src_ip"],
    ),
    "email": SourceSpec(
        "email.jsonl",
        "jsonl",
        lambda e: (
            e["direction"],
            _mail_domain(e["sender"]),
            e["verdict"],
            e["action"],
            e["spf"],
            e["dkim"],
            e["dmarc"],
            bool(e["attachments"]),
        ),
        lambda e: (e["recipients"] or [""])[0],
    ),
    "ecom_auth": SourceSpec(
        "ecom_auth.jsonl",
        "jsonl",
        lambda e: (e["result"], e["failure_reason"], e["captcha"], ua_family(e["user_agent"])),
        lambda e: e["customer_id"],
    ),
    "email_clicks": SourceSpec(
        "email_clicks.jsonl",
        "jsonl",
        lambda e: (urlparse(e["url"]).netloc, e["action"], e["verdict_at_click"]),
        lambda e: e["user"],
    ),
    "vpn": SourceSpec(
        "vpn.jsonl", "jsonl", lambda e: (e["action"], e["country"], e["mfa_result"]), lambda e: e["user"]
    ),
    "ai_gateway": SourceSpec(
        "ai_gateway.jsonl",
        "jsonl",
        lambda e: (
            e["authenticated"],
            e["response_summary"],
            tuple(sorted({t["name"] for t in e["tool_calls"]})),
            e["guardrail"]["triggered"],
            e["guardrail"]["action"],
        ),
        lambda e: e["customer_id"] or e["src_ip"],
    ),
    "ecom_account": SourceSpec(
        "ecom_account.jsonl",
        "jsonl",
        lambda e: (e["event"], _details(e).get("payment", "")),
        lambda e: e["customer_id"],
    ),
    "cloudtrail": SourceSpec(
        "cloudtrail.jsonl",
        "jsonl",
        lambda e: (
            e["eventName"],
            e["eventSource"],
            e["userIdentity"].get("userName"),
            ua_family(e["userAgent"]),
            e["errorCode"],
        ),
        lambda e: "*",  # the actor is already part of the template
    ),
    "sql_audit": SourceSpec(
        "sql_audit.jsonl",
        "jsonl",
        lambda e: (e["user"], e["client_host"], e["database"], e["statement_type"], e["object"]),
        lambda e: e["client_host"],
    ),
    "dlp": SourceSpec(
        "dlp.jsonl", "jsonl", lambda e: (e["channel"], e["destination"], e["policy"], e["action"]), lambda e: e["user"]
    ),
    "idp_audit": SourceSpec(
        "idp_audit.jsonl",
        "jsonl",
        lambda e: (e["operation"], _details(e).get("initiated_by")),
        lambda e: e["actor_upn"],
    ),
    "cicd_builds": SourceSpec(
        "cicd_builds.jsonl",
        "jsonl",
        lambda e: (e["pipeline"], e["step"], e["status"], bool(_details(e).get("new_packages"))),
        lambda e: "*",  # the pipeline is already part of the template
    ),
    "ad_events": SourceSpec(
        "ad_events.jsonl", "jsonl", lambda e: (e["event_code"], e["subject"], e["src_host"]), lambda e: e["target"]
    ),
}


def normalise_identity(value: Any) -> str:
    """Lower-case identity without domain prefix (TARVIA\\x) or UPN suffix (x@tarvia.example)."""
    text = str(value).lower()
    return text.split("\\")[-1].split("@")[0]
