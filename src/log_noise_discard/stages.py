"""Noise stages N1-N3 over the logs cited by alerts.

Why: each stage removes one kind of log that adds no information for prioritising alerts. Stages only decide
which event_ids to discard; they never touch the source data.

- N1: duplicate inside an alert (same alert, source, template and entity as an earlier cited log).
- N2: the same event_id is cited by two or more alerts (it cannot tell those alerts apart).
- N3: the same template appears in >= tau of the alerts of a rule and its entity is already in each alert;
      one representative per (rule, source, template) is kept, protected rules are skipped.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .config import NoiseFilterConfig
from .templates import normalise_identity

GroupKey = tuple[str, str, tuple]


@dataclass(frozen=True)
class LogRecord:
    """One cited log event reduced to what the stages need, plus the raw event."""

    event_id: str
    source: str
    template: tuple
    entity: str
    size: int
    event: Mapping[str, Any]


@dataclass
class NoiseGroup:
    """N3 group: alerts of one rule that all carry the same log content."""

    rule_id: str
    source: str
    template: tuple
    representative_event_id: str
    discarded_event_ids: list[str] = field(default_factory=list)
    alert_ids: list[str] = field(default_factory=list)
    varying_values: dict[str, list[Any]] = field(default_factory=dict)


def alert_values(alert: Mapping[str, Any]) -> frozenset[str]:
    """Every string in the alert entities and evidence, raw-lowercase and identity-normalised."""
    values: set[str] = set()
    stack: list[Any] = [alert.get("entities", {}), alert.get("evidence", {})]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            values.update((item.lower(), normalise_identity(item)))
        elif isinstance(item, Mapping):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return frozenset(values)


def stage_n1(records: Mapping[str, LogRecord], ev_alerts: Mapping[str, list[str]]) -> set[str]:
    """Logs whose every citing alert already cites an identical (source, template, entity) log."""
    seen: set[tuple] = set()
    discarded: set[str] = set()
    for eid in sorted(records):
        rec = records[eid]
        keys = [(aid, rec.source, rec.template, rec.entity) for aid in ev_alerts[eid]]
        if all(k in seen for k in keys):
            discarded.add(eid)
        seen.update(keys)
    return discarded


def stage_n2(candidates: Iterable[str], ev_alerts: Mapping[str, list[str]]) -> set[str]:
    """Logs cited by two or more alerts."""
    return {eid for eid in candidates if len(ev_alerts[eid]) >= 2}


def _non_discriminant_keys(
    candidates: list[str],
    records: Mapping[str, LogRecord],
    ev_alerts: Mapping[str, list[str]],
    alerts: Mapping[str, Mapping[str, Any]],
    cfg: NoiseFilterConfig,
) -> set[GroupKey]:
    rule_size = Counter(a["rule_id"] for a in alerts.values())
    key_alerts: dict[GroupKey, set[str]] = defaultdict(set)
    for eid in candidates:
        rec = records[eid]
        for aid in ev_alerts[eid]:
            key_alerts[(alerts[aid]["rule_id"], rec.source, rec.template)].add(aid)
    return {
        k
        for k, aids in key_alerts.items()
        if rule_size[k[0]] >= cfg.min_rule_alerts and len(aids) >= cfg.tau * rule_size[k[0]]
    }


def _entity_in_alerts(rec: LogRecord, aids: list[str], values: Mapping[str, frozenset[str]]) -> bool:
    norm = normalise_identity(rec.entity)
    return all(rec.entity in values[a] or norm in values[a] for a in aids)


def stage_n3(
    candidates: Iterable[str],
    records: Mapping[str, LogRecord],
    ev_alerts: Mapping[str, list[str]],
    alerts: Mapping[str, Mapping[str, Any]],
    severity: Mapping[str, str],
    cfg: NoiseFilterConfig,
) -> tuple[set[str], list[NoiseGroup]]:
    """Non-discriminant logs inside a rule; returns discarded ids and one group per kept representative."""
    ordered = sorted(candidates)
    nondisc = _non_discriminant_keys(ordered, records, ev_alerts, alerts, cfg)
    values = {aid: alert_values(a) for aid, a in alerts.items()}
    groups: dict[GroupKey, NoiseGroup] = {}
    discarded: set[str] = set()
    for eid in ordered:
        rec, aids = records[eid], ev_alerts[eid]
        keys = {(alerts[a]["rule_id"], rec.source, rec.template) for a in aids}
        rule_id = alerts[aids[0]]["rule_id"]
        if not keys <= nondisc or not _entity_in_alerts(rec, aids, values):
            continue
        if cfg.is_protected(rule_id, severity.get(rule_id, "")):
            continue
        key = (rule_id, rec.source, rec.template)
        if key not in groups:
            groups[key] = NoiseGroup(rule_id, rec.source, rec.template, eid, alert_ids=list(aids))
            continue
        group = groups[key]
        group.discarded_event_ids.append(eid)
        group.alert_ids.extend(aids)
        for name in cfg.varying_fields.get(rec.source, ()):
            group.varying_values.setdefault(name, []).append(rec.event.get(name))
        discarded.add(eid)
    return discarded, [groups[k] for k in sorted(groups, key=lambda k: (k[0], k[1], repr(k[2])))]
