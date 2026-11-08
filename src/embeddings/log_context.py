"""Per-alert selection of diverse log evidence.

The selector works on the informative log inventory produced by ``log_noise_discard``.
It gives every alert its own budget instead of taking one global top-k list, while
keeping a source quota and avoiding repeated events with the same template.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..log_noise_discard.context import parse_ts
from ..log_noise_discard.loaders import iter_source
from ..log_noise_discard.stages import LogRecord, alert_values
from ..log_noise_discard.templates import SOURCES, normalise_identity


PRODUCT_SOURCES: dict[str, tuple[str, ...]] = {
    "EDR": ("edr_events",),
    "WAF": ("waf", "proxy", "dns", "firewall"),
    "EMAIL_GW": ("email", "email_clicks", "proxy", "dns"),
    "IDP": ("idp_signins", "idp_audit", "vpn", "ad_events"),
    "PROXY": ("proxy", "dns", "firewall", "edr_events"),
    "DNS": ("dns", "proxy", "firewall", "edr_events"),
    "AI_GATEWAY": ("ai_gateway", "proxy", "ecom_auth"),
    "DLP": ("dlp", "proxy", "email", "sql_audit"),
    "CLOUD": ("cloudtrail", "idp_signins", "edr_events"),
    "NGFW": ("firewall", "vpn", "proxy", "dns"),
    "ECOM": ("ecom_auth", "ecom_account", "ai_gateway", "firewall"),
    "CICD": ("cicd_builds", "cloudtrail", "edr_events"),
    "VPN": ("vpn", "idp_signins", "firewall"),
    "AD": ("ad_events", "idp_audit", "edr_events"),
}

_GENERIC_VALUES = {"system", "true", "false", "none", "low", "medium", "high", "critical", "blocked", "allowed"}


@dataclass(frozen=True)
class SelectedLog:
    """A selected event and the reason it was useful for one alert."""

    event_id: str
    source: str
    score: float
    reason: str
    event: Mapping[str, Any]


def _event_strings(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value.lower(), normalise_identity(value)}
    if isinstance(value, Mapping):
        out: set[str] = set()
        for item in value.values():
            out.update(_event_strings(item))
        return out
    if isinstance(value, list):
        out = set()
        for item in value:
            out.update(_event_strings(item))
        return out
    return set()


def _score(alert: Mapping[str, Any], record: LogRecord, alert_ts: datetime, values: set[str], preferred: tuple[str, ...]) -> tuple[float, str]:
    event = record.event
    event_values = _event_strings(event)
    shared = values & event_values
    cited = record.event_id in (alert.get("related_events") or [])
    if not shared and not cited:
        return -1.0, "sin entidad común"
    delta_minutes = abs((parse_ts(str(event.get("timestamp"))) - alert_ts).total_seconds()) / 60
    if delta_minutes > 24 * 60:
        return -1.0, "fuera de ventana ±24h"

    score = 0.0
    reasons: list[str] = []
    if record.source in preferred:
        score += 2.0 - min(preferred.index(record.source) * 0.25, 1.5)
        reasons.append("fuente relacionada")
    if shared:
        score += min(4.0, 1.5 + 0.5 * len(shared))
        reasons.append("entidad compartida")
    score += max(0.0, 2.0 - delta_minutes / 720)
    if delta_minutes <= 15:
        reasons.append("ventana inmediata")
    elif delta_minutes <= 120:
        reasons.append("ventana próxima")
    if cited:
        score += 3.0
        reasons.append("citado por la alerta")
    return score, ", ".join(reasons) or "contexto temporal"


def _candidate_values(alert: Mapping[str, Any]) -> set[str]:
    """Values useful for joining logs, excluding common status words."""
    return {value for value in alert_values(alert) if len(value) >= 3 and value not in _GENERIC_VALUES}


def collect_dataset_candidates(data_dir: str, alert: Mapping[str, Any], max_candidates: int = 100) -> list[LogRecord]:
    """Stream the dataset once and retain only entity/time candidates for one alert.

    This is deliberately a candidate collector, not a full log loader: raw events are kept only when they
    share a useful value with the alert and fall in the correlation window. ``select_log_context`` applies
    the final per-source budget and diversity rules afterwards.
    """
    values = _candidate_values(alert)
    alert_ts = parse_ts(str(alert["created_at"]))
    preferred = PRODUCT_SOURCES.get(str(alert.get("source_product", "")).upper(), ())
    candidates_by_source: defaultdict[str, list[LogRecord]] = defaultdict(list)
    for source, spec in SOURCES.items():
        for event, size in iter_source(Path(data_dir), spec):
            event_values = _event_strings(event)
            if not values & event_values:
                continue
            record = LogRecord(event["event_id"], source, spec.template(event), str(spec.entity(event)).lower(), size, event)
            score, _ = _score(alert, record, alert_ts, values, preferred)
            if score >= 0:
                candidates_by_source[source].append(record)
                if len(candidates_by_source[source]) > max_candidates * 2:
                    ranked = sorted(
                        candidates_by_source[source],
                        key=lambda item: (-_score(alert, item, alert_ts, values, preferred)[0], item.event_id),
                    )
                    candidates_by_source[source] = ranked[:max_candidates]
    return [record for source in sorted(candidates_by_source) for record in candidates_by_source[source]]


def collect_dataset_candidates_for_alerts(
    data_dir: str, alerts: Mapping[str, Mapping[str, Any]], max_candidates: int = 100
) -> dict[str, list[LogRecord]]:
    """Collect candidates for many alerts in one pass over the raw sources.

    The index maps alert entity values to alert IDs. Raw events are never retained globally;
    only bounded per-alert/per-source candidate lists are kept.
    """
    value_to_alerts: defaultdict[str, set[str]] = defaultdict(set)
    for alert_id, alert in alerts.items():
        for value in _candidate_values(alert):
            value_to_alerts[value].add(alert_id)

    candidates: dict[str, defaultdict[str, list[LogRecord]]] = {
        alert_id: defaultdict(list) for alert_id in alerts
    }
    for source, spec in SOURCES.items():
        for event, size in iter_source(Path(data_dir), spec):
            matched_ids: set[str] = set()
            for value in _event_strings(event):
                matched_ids.update(value_to_alerts.get(value, ()))
            for alert_id in matched_ids:
                alert = alerts[alert_id]
                record = LogRecord(event["event_id"], source, spec.template(event), str(spec.entity(event)).lower(), size, event)
                score, _ = _score(
                    alert,
                    record,
                    parse_ts(str(alert["created_at"])),
                    _candidate_values(alert),
                    PRODUCT_SOURCES.get(str(alert.get("source_product", "")).upper(), ()),
                )
                if score < 0:
                    continue
                bucket = candidates[alert_id][source]
                bucket.append(record)
                if len(bucket) > max_candidates * 2:
                    bucket.sort(
                        key=lambda item: (
                            -_score(
                                alert,
                                item,
                                parse_ts(str(alert["created_at"])),
                                _candidate_values(alert),
                                PRODUCT_SOURCES.get(str(alert.get("source_product", "")).upper(), ()),
                            )[0],
                            item.event_id,
                        )
                    )
                    del bucket[max_candidates:]
    return {
        alert_id: [record for source in sorted(by_source) for record in by_source[source]]
        for alert_id, by_source in candidates.items()
    }


def select_log_context(
    alert: Mapping[str, Any],
    candidates: Iterable[LogRecord],
    budget: int = 20,
    per_source: int = 5,
) -> list[SelectedLog]:
    """Select up to ``budget`` logs for one alert with per-source diversity."""
    if budget <= 0 or per_source <= 0:
        return []
    records = list(candidates)
    alert_ts = parse_ts(str(alert["created_at"]))
    values = set(alert_values(alert))
    preferred = PRODUCT_SOURCES.get(str(alert.get("source_product", "")).upper(), ())
    ranked: list[SelectedLog] = []
    templates_by_event = {record.event_id: record.template for record in records}
    for record in records:
        score, reason = _score(alert, record, alert_ts, values, preferred)
        if score >= 0:
            ranked.append(SelectedLog(record.event_id, record.source, score, reason, record.event))
    ranked.sort(key=lambda item: (-item.score, item.source, item.event_id))

    selected: list[SelectedLog] = []
    source_counts: defaultdict[str, int] = defaultdict(int)
    templates: set[tuple[str, tuple]] = set()
    for item in ranked:
        key = (item.source, templates_by_event[item.event_id])
        if source_counts[item.source] >= per_source or key in templates:
            continue
        selected.append(item)
        source_counts[item.source] += 1
        templates.add(key)
        if len(selected) >= budget:
            return selected

    # If a source has fewer diverse events, fill the remaining budget globally.
    selected_ids = {item.event_id for item in selected}
    for item in ranked:
        key = (item.source, templates_by_event[item.event_id])
        if item.event_id not in selected_ids and key not in templates:
            selected.append(item)
            selected_ids.add(item.event_id)
            templates.add(key)
            if len(selected) >= budget:
                break
    return selected


def log_context_text(selected: Iterable[SelectedLog]) -> str:
    """Render selected logs for a future context embedding, excluding raw free text."""
    rows = []
    for item in selected:
        event = item.event
        safe = {
            "event_id": item.event_id,
            "source": item.source,
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type") or event.get("eventName") or event.get("event"),
            "action": event.get("action") or event.get("result") or event.get("status"),
            "hostname": event.get("hostname") or event.get("client_host") or event.get("src_host"),
            "user": event.get("user") or event.get("user_upn") or event.get("actor_upn"),
            "src_ip": event.get("src_ip") or event.get("sourceIPAddress"),
            "domain": event.get("domain") or event.get("query"),
            "selection_reason": item.reason,
        }
        rows.append(json.dumps({k: v for k, v in safe.items() if v not in (None, "")}, ensure_ascii=False, sort_keys=True))
    return "\n".join(rows)
