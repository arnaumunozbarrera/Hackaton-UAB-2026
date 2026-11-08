"""Orchestration of the log noise filter.

Why: other pipeline steps (context builder, LLM triage, correlation) need a single call that returns only the
informative logs per alert, plus the reason why every other cited log was set aside. Nothing is deleted:
the result is a selection over the read-only dataset.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import NoiseFilterConfig
from .context import Context, load_context
from .explained import Explanation, stage_n4
from .loaders import iter_source, load_alerts, load_rule_severity
from .stages import LogRecord, NoiseGroup, stage_n1, stage_n2, stage_n3
from .templates import SOURCES

STAGE_DESCRIPTIONS = {
    "N0": "Log not cited in related_events of any alert",
    "N1": "Duplicate inside an alert (same source, template and entity)",
    "N2": "Same event_id cited by two or more alerts",
    "N3": "Same content in >= tau of a rule's alerts, entity already in the alert (1 representative kept)",
    "N4": "Activity explained by authoritative context, no free-text field, not guarded",
}


@dataclass(frozen=True)
class StageStat:
    stage: str
    description: str
    discarded_events: int
    discarded_bytes: int
    remaining_events: int
    remaining_bytes: int


@dataclass
class FilterResult:
    """Selection of informative logs. `kept` and `discarded` together cover every cited log."""

    kept: dict[str, LogRecord]
    discarded: dict[str, str]  # event_id -> stage (N1/N2/N3); N0 logs are never loaded
    alert_events: dict[str, list[str]]  # alert_id -> kept event_ids, sorted
    groups: list[NoiseGroup] = field(default_factory=list)
    stats: list[StageStat] = field(default_factory=list)
    explanations: dict[str, Explanation] = field(default_factory=dict)  # N4 discarded -> context reference
    open_text_kept: dict[str, Explanation] = field(default_factory=dict)  # explained but kept (free text)
    guarded: dict[str, str] = field(default_factory=dict)  # explained but kept by a guard (G1/G2)
    discarded_records: dict[str, LogRecord] = field(default_factory=dict)  # content of discarded cited logs

    def kept_for_alert(self, alert_id: str) -> list[LogRecord]:
        """Informative logs of one alert."""
        return [self.kept[eid] for eid in self.alert_events.get(alert_id, [])]

    def iter_kept(self) -> Iterator[LogRecord]:
        """Every informative log, in event_id order."""
        return (self.kept[eid] for eid in sorted(self.kept))


def _index_alerts(alerts: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    ev_alerts: dict[str, set[str]] = defaultdict(set)
    for aid, alert in alerts.items():
        for eid in alert.get("related_events") or []:
            ev_alerts[eid].add(aid)
    return {eid: sorted(aids) for eid, aids in ev_alerts.items()}


def _load_cited(
    data_dir: Path, cited: dict[str, list[str]], ctx: Context | None
) -> tuple[dict[str, LogRecord], int, int]:
    """Stream every source once; keep only cited events. Returns records, total events and total bytes."""
    records: dict[str, LogRecord] = {}
    total_events = total_bytes = 0
    for source, spec in SOURCES.items():
        for event, size in iter_source(data_dir, spec):
            total_events += 1
            total_bytes += size
            if ctx is not None:
                ctx.observe(source, event)
            eid = event["event_id"]
            if eid in cited:
                entity = str(spec.entity(event)).lower()
                records[eid] = LogRecord(eid, source, spec.template(event), entity, size, event)
    return records, total_events, total_bytes


class _Ledger:
    """Tracks remaining events/bytes and builds the stage table."""

    def __init__(self, events: int, size: int) -> None:
        self.events, self.size = events, size
        self.stats: list[StageStat] = []

    def apply(self, stage: str, ids: set[str], records: dict[str, LogRecord]) -> None:
        removed = sum(records[e].size for e in ids)
        self.events -= len(ids)
        self.size -= removed
        self.stats.append(StageStat(stage, STAGE_DESCRIPTIONS[stage], len(ids), removed, self.events, self.size))


def run_filter(data_dir: str | Path = "docs", config: NoiseFilterConfig | None = None) -> FilterResult:
    """Apply N0-N3 and return only the informative logs, without modifying any file."""
    cfg = config or NoiseFilterConfig()
    data = Path(data_dir)
    alerts = load_alerts(data)
    ev_alerts = _index_alerts(alerts)
    ctx = load_context(data) if "N4" in cfg.stages else None
    records, total_events, total_bytes = _load_cited(data, ev_alerts, ctx)
    ledger = _Ledger(total_events, total_bytes)
    n0 = total_events - len(records)
    ledger.events -= n0
    ledger.size = sum(r.size for r in records.values())
    ledger.stats.append(
        StageStat("N0", STAGE_DESCRIPTIONS["N0"], n0, total_bytes - ledger.size, ledger.events, ledger.size)
    )
    discarded: dict[str, str] = {}
    groups: list[NoiseGroup] = []
    n4 = None
    severity = load_rule_severity(data)
    remaining = set(records)
    for stage in cfg.stages:
        if stage == "N1":
            ids = stage_n1(records, ev_alerts)
        elif stage == "N2":
            ids = stage_n2(remaining, ev_alerts)
        elif stage == "N3":
            ids, groups = stage_n3(remaining, records, ev_alerts, alerts, severity, cfg)
        else:
            assert ctx is not None
            n4 = stage_n4(remaining, records, alerts, severity, ctx, cfg)
            ids = set(n4.discarded)
        ids &= remaining
        remaining -= ids
        discarded.update(dict.fromkeys(ids, stage))
        ledger.apply(stage, ids, records)
    kept = {eid: records[eid] for eid in sorted(remaining)}
    alert_events = {aid: [e for e in ev_alerts_for(aid, alerts) if e in kept] for aid in sorted(alerts)}
    result = FilterResult(kept, dict(sorted(discarded.items())), alert_events, groups, ledger.stats)
    result.discarded_records = {eid: records[eid] for eid in sorted(discarded)}
    if n4 is not None:
        result.explanations, result.open_text_kept, result.guarded = n4.discarded, n4.open_text_kept, n4.guarded
    return result


def ev_alerts_for(alert_id: str, alerts: dict[str, dict[str, Any]]) -> list[str]:
    """Cited event_ids of one alert, sorted and de-duplicated."""
    return sorted(set(alerts[alert_id].get("related_events") or []))
