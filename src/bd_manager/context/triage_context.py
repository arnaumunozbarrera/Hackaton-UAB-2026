"""Read-only context builder for the Tarvia SOC triage database.

Assumptions discovered during repository inspection:
* ``db.build_db`` is the authoritative star-schema DDL (``fact_alert``,
  ``dim_log``, ``dim_user``, ``dim_vulnerability``, ``dim_context`` and the
  bridge/views); older compatibility databases may expose the same names via
  views.
* The severity matrix and criticality names come from ``ref_severity_matrix``
  and ``docs/01_contexto/politica_soc.md``.  ``Alta`` and ``Crítica`` are the
  high-impact guard values.
* Existing repository correlation definitions are the source for approved
  changes, malicious IOC intelligence, duplicate hashes, and authorised
  activity.  No indicator list is copied into this module.
* The repository does not define a separate deduplication algorithm for a raw
  alert, so this builder does not invent a ``dedup_hash`` for the input.

The manager is deliberately a SELECT-only boundary.  It opens SQLite with
``mode=ro`` and installs an authorizer which rejects all write/schema/pragma
operations, including accidental writes made by future code.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

LOG = logging.getLogger(__name__)
ALERT_WINDOW_HOURS = 24
LOG_WINDOW_MINUTES = 10
SCHEMA_VERSION = "1.0"
SEVERITIES = ("informational", "low", "medium", "high", "critical")
VERDICTS = ("true_positive", "benign_true_positive", "false_positive", "needs_more_info")
COMPONENT_WEIGHTS = {
    "rule": 0.15,
    "technique": 0.15,
    "entity_overlap": 0.20,
    "user": 0.10,
    "asset": 0.15,
    "ioc": 0.05,
    "incident": 0.10,
    "duplicate": 0.10,
}


@dataclass(frozen=True)
class Config:
    """All tunables live here; the two search windows are intentionally fixed."""

    similar_min_score: float = 0.20  # TODO: tune with SOC evaluation data.
    similar_top_n: int = 20  # TODO: tune prompt budget.
    max_prioritised_events: int = 50  # TODO: tune prompt budget.
    max_contiguous_logs: int = 100  # TODO: tune prompt budget.
    max_sample_logs: int = 30  # TODO: tune prompt budget.
    max_chars_detail: int = 12000  # TODO: tune after sanitisation stage exists.
    max_chars_evidence: int = 12000  # TODO: tune after sanitisation stage exists.
    prefilter_enabled: bool = True
    safety_guard_enabled: bool = True
    include_change_overlap: bool = True
    include_duplicate_groups: bool = True
    flag_only_filters: bool = True


@dataclass(frozen=True)
class Filter:
    filter_id: str
    name: str
    category: str
    target: str
    match: Callable[[dict[str, Any]], tuple[str, str] | None]
    enabled: bool = True
    withhold: bool = True
    override_guard: bool = False


def normalise_time(value: str | None) -> str | None:
    """Match the repository views: first 16 chars, T replaced by a space."""
    return value and value[:16].replace("T", " ")


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        try:
            dt = datetime.strptime(normalise_time(value), "%Y-%m-%d %H:%M")
        except (TypeError, ValueError):
            return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _json(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value) if isinstance(value, str) else value
    except (TypeError, json.JSONDecodeError):
        return default


def _flat_entities(raw: dict[str, Any]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for entity_type, values in (raw.get("entities") or {}).items():
        if not isinstance(values, list):
            values = [values]
        for value in values:
            if isinstance(value, dict):
                for key, item in value.items():
                    if item not in (None, "") and key not in {"display_name", "parent"}:
                        result.append({"entity_type": entity_type.rstrip("s"), "entity_value": str(item)})
            elif value not in (None, ""):
                result.append({"entity_type": entity_type.rstrip("s"), "entity_value": str(value)})
    return result


class ContextManager:
    """Build one JSON-compatible context package without changing the DB."""

    def __init__(self, database: str | Path, config: Config | None = None, filters: Iterable[Filter] | None = None):
        self.database = Path(database)
        self.config = config or Config()
        self.filters = tuple(filters) if filters is not None else self._default_filters()
        self.errors: list[dict[str, str]] = []
        self.withheld: list[dict[str, Any]] = []
        self.guard_count = 0

    def connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(f"file:{self.database}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        blocked = {
            sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_TEMP_INDEX,
            sqlite3.SQLITE_CREATE_TEMP_TABLE, sqlite3.SQLITE_CREATE_TEMP_TRIGGER, sqlite3.SQLITE_CREATE_TEMP_VIEW,
            sqlite3.SQLITE_CREATE_TRIGGER, sqlite3.SQLITE_CREATE_VIEW, sqlite3.SQLITE_DELETE,
            sqlite3.SQLITE_DROP_INDEX, sqlite3.SQLITE_DROP_TABLE, sqlite3.SQLITE_DROP_TEMP_INDEX,
            sqlite3.SQLITE_DROP_TEMP_TABLE, sqlite3.SQLITE_DROP_TEMP_TRIGGER, sqlite3.SQLITE_DROP_TEMP_VIEW,
            sqlite3.SQLITE_DROP_TRIGGER, sqlite3.SQLITE_DROP_VIEW, sqlite3.SQLITE_INSERT, sqlite3.SQLITE_PRAGMA,
            sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_ALTER_TABLE,
        }

        def authorizer(action: int, _arg1: str | None, _arg2: str | None, _db: str | None, _source: str | None) -> int:
            return sqlite3.SQLITE_DENY if action in blocked else sqlite3.SQLITE_OK

        con.set_authorizer(authorizer)
        return con

    @staticmethod
    def _default_filters() -> tuple[Filter, ...]:
        def db_reputation(item: dict[str, Any]) -> tuple[str, str] | None:
            context = item.get("context") or {}
            rep = context.get("reputation")
            if rep in {"malicious", "bad", "harmful"}:
                return "context_key", str(context.get("context_key"))
            if context.get("sandbox_verdict") in {"malicious", "malware"}:
                return "context_key", str(context.get("context_key"))
            return None

        def approved(item: dict[str, Any]) -> tuple[str, str] | None:
            overlaps = item.get("change_overlap") or []
            hit = next((x for x in overlaps if x.get("entity_match")), None)
            return ("change_id", str(hit["change_id"])) if hit else None

        def duplicate(item: dict[str, Any]) -> tuple[str, str] | None:
            return ("alert_id", str(item["alert_id"])) if item.get("is_duplicate") else None

        return (
            Filter("PF-MAL-IOC", "Known malicious indicator", "known_malicious_hash", "alert", db_reputation),
            Filter("PF-APPROVED-CHANGE", "Approved change overlap", "approved_change", "alert", approved),
            Filter("PF-DUPLICATE", "Known duplicate alert", "duplicate", "similar_alert", duplicate),
            Filter("PF-KNOWN-IOC-LOG", "Known malicious log indicator", "known_malicious_hash", "log", db_reputation),
        )

    def _query(self, con: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        return list(con.execute(sql, params))

    def normalise(self, raw: dict[str, Any], con: sqlite3.Connection) -> dict[str, Any]:
        entities = _flat_entities(raw)
        resolved: list[dict[str, Any]] = []
        for item in entities:
            value = item["entity_value"]
            kind = item["entity_type"]
            user = None
            host = None
            context = None
            if kind == "user":
                user = self._query(con, "SELECT * FROM dim_user WHERE lower(upn)=lower(?) OR lower(username)=lower(?) LIMIT 1", (value, value))
            if kind == "host":
                host = self._query(con, "SELECT * FROM dim_vulnerability WHERE hostname=? LIMIT 1", (value,))
            if kind in {"ip", "domain", "url", "file", "sha256"}:
                context = self._query(con, "SELECT * FROM dim_context WHERE context_key=? LIMIT 1", (value,))
            resolved.append({"entity_type": kind, "entity_value": value, "user_key": user[0]["user_key"] if user else None,
                             "hostname": host[0]["hostname"] if host else None, "context_key": context[0]["context_key"] if context else None})
        users = [x["user_key"] for x in resolved if x.get("user_key")]
        hosts = [x["hostname"] for x in resolved if x.get("hostname")]
        iocs = [x["context_key"] for x in resolved if x.get("context_key")]
        return {"alert_id": raw.get("alert_id"), "created_at": normalise_time(raw.get("created_at")),
                "source_product": raw.get("source_product"), "rule_id": raw.get("rule_id"),
                "rule_name": raw.get("rule_name"), "rule_severity": raw.get("severity"),
                "status": raw.get("status"), "technique_id": (raw.get("mitre") or {}).get("technique_id"),
                "mitre_tactic": (raw.get("mitre") or {}).get("tactic"), "runbook": raw.get("runbook"),
                "users": users, "hosts": hosts, "contexts": iocs, "event_ids": raw.get("related_events") or [],
                "entities": entities, "resolved_entities": resolved, "dedup_hash": None}

    @staticmethod
    def _entity_set(rows: Iterable[sqlite3.Row | dict[str, Any]]) -> set[tuple[str, str]]:
        return {(str(r["entity_type"]), str(r["entity_value"])) for r in rows}

    def _similar_score(self, source: dict[str, Any], candidate: dict[str, Any], source_entities: set[tuple[str, str]], candidate_entities: set[tuple[str, str]]) -> tuple[float, dict[str, float]]:
        rule = 1.0 if source.get("rule_id") == candidate.get("rule_id") else (0.6 if source.get("runbook") and source.get("runbook") == candidate.get("runbook") else 0.0)
        tech = 1.0 if source.get("technique_id") == candidate.get("technique_id") and source.get("technique_id") else (0.4 if source.get("mitre_tactic") == candidate.get("mitre_tactic") and source.get("mitre_tactic") else 0.0)
        union = source_entities | candidate_entities
        overlap = len(source_entities & candidate_entities) / len(union) if union else 0.0
        user = 1.0 if set(source.get("users", [])) & set(candidate.get("users", [])) else 0.0
        asset = 1.0 if set(source.get("hosts", [])) & set(candidate.get("hosts", [])) else 0.0
        ioc = 1.0 if set(source.get("contexts", [])) & set(candidate.get("contexts", [])) else 0.0
        incident = 1.0 if set(source.get("incident_ids", [])) & set(candidate.get("incident_ids", [])) else 0.0
        duplicate = 1.0 if source.get("dedup_hash") and source.get("dedup_hash") == candidate.get("dedup_hash") else 0.0
        scores = {"rule": rule, "technique": tech, "entity_overlap": overlap, "user": user, "asset": asset, "ioc": ioc, "incident": incident, "duplicate": duplicate}
        return sum(COMPONENT_WEIGHTS[k] * v for k, v in scores.items()), scores

    def _enrich_alert(self, row: sqlite3.Row, con: sqlite3.Connection) -> dict[str, Any]:
        d = dict(row)
        d["entities_set"] = self._entity_set(self._query(con, "SELECT entity_type, entity_value FROM bridge_alert_entity WHERE alert_id=?", (d["alert_id"],)))
        d["users"] = [x[0] for x in self._query(con, "SELECT DISTINCT user_key FROM bridge_alert_entity WHERE alert_id=? AND user_key IS NOT NULL", (d["alert_id"],))]
        d["hosts"] = [x[0] for x in self._query(con, "SELECT DISTINCT hostname FROM bridge_alert_entity WHERE alert_id=? AND hostname IS NOT NULL", (d["alert_id"],))]
        d["contexts"] = [x[0] for x in self._query(con, "SELECT DISTINCT context_key FROM bridge_alert_entity WHERE alert_id=? AND context_key IS NOT NULL", (d["alert_id"],))]
        d["context"] = next((dict(x) for x in self._query(con, "SELECT * FROM dim_context WHERE context_key=?", (d.get("context_key"),))), None) if d.get("context_key") else None
        d["incident_ids"] = [x[0] for x in self._query(con, "SELECT incident_id FROM bridge_alert_incident WHERE alert_id=?", (d["alert_id"],))]
        d["change_overlap"] = [dict(x) for x in self._query(con, "SELECT * FROM v_alert_change_overlap WHERE alert_id=?", (d["alert_id"],))] if self.config.include_change_overlap else []
        d["is_duplicate"] = bool(self._query(con, "SELECT 1 FROM v_alert_duplicates WHERE instr(',' || alert_ids || ',', ',' || ? || ',') > 0 LIMIT 1", (d["alert_id"],))) if self.config.include_duplicate_groups else False
        return d

    def _flag(self, item: dict[str, Any], target: str) -> dict[str, Any]:
        matches = []
        for flt in self.filters:
            allowed_targets = {target}
            if target in {"input_alert", "similar_alert"}:
                allowed_targets.add("alert")
            if not self.config.prefilter_enabled or not flt.enabled or flt.target not in allowed_targets:
                continue
            try:
                hit = flt.match(item)
                if hit:
                    matches.append((flt, hit))
            except Exception as exc:  # fail open by contract
                self.errors.append({"filter_id": flt.filter_id, "error": str(exc)})
                LOG.exception("prefilter %s failed", flt.filter_id)
        if not matches:
            return {"evaluated": True, "matched": False}
        flt, (matched_field, reference) = matches[0]
        guarded = self.config.safety_guard_enabled and not flt.override_guard and self._guarded(item)
        if guarded:
            self.guard_count += 1
            return {"evaluated": True, "matched": True, "filter_id": flt.filter_id, "filter_category": flt.category, "action": "flag_only", "guard_applied": True}
        if flt.withhold:
            self.withheld.append({"item_type": target, "item_id": item.get("alert_id") or item.get("event_id"), "filter_id": flt.filter_id, "filter_name": flt.name, "filter_category": flt.category, "matched_field": matched_field, "matched_value_reference": reference, "decision": "withheld"})
            return {"evaluated": True, "matched": True, "withhold": True}
        return {"evaluated": True, "matched": True, "filter_id": flt.filter_id, "filter_category": flt.category, "action": "flag_only"}

    @staticmethod
    def _guarded(item: dict[str, Any]) -> bool:
        if item.get("rule_severity") in {"high", "critical"}:
            return True
        user = item.get("user") or {}
        asset = item.get("asset") or {}
        return bool(user.get("privileged") or user.get("vip") or asset.get("criticality") in {"Alta", "Crítica", "Critica"})

    def _log_item(self, row: sqlite3.Row, kind: str = "contiguous_log") -> dict[str, Any]:
        d = dict(row)
        d["detail"] = _json(d.get("detail"), d.get("detail"))
        d["untrusted_content"] = True
        d["prefilter_flag"] = self._flag(d, "log")
        return d

    def build(self, raw: dict[str, Any]) -> dict[str, Any]:
        self.errors.clear(); self.withheld.clear(); self.guard_count = 0
        generated = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with self.connect() as con:
            normal = self.normalise(raw, con)
            input_item = dict(normal)
            input_item["context"] = next((dict(x) for x in self._query(con, "SELECT * FROM dim_context WHERE context_key=?", (normal["contexts"][0],))), None) if normal["contexts"] else None
            input_item["rule_severity"] = normal.get("rule_severity")
            input_item["change_overlap"] = [dict(x) for x in self._query(con, "SELECT * FROM v_alert_change_overlap WHERE alert_id=?", (normal["alert_id"],))] if normal["alert_id"] else []
            input_flag = self._flag(input_item, "input_alert")
            meta = {"generated_at": generated, "window_alert_hours": ALERT_WINDOW_HOURS, "window_log_minutes": LOG_WINDOW_MINUTES, "schema_version": SCHEMA_VERSION, "truncation": {}, "prefilter": {"enabled": self.config.prefilter_enabled, "decision": "withheld_input" if input_flag.get("withhold") else "retained", "withheld_counts": {}, "guard_applied_count": 0, "errors": self.errors}}
            base = {"meta": meta, "input_alert": {"raw": raw, "normalised": normal, "resolved_entities": normal["resolved_entities"], "enrichment": {}, "prefilter_flag": input_flag}, "similar_alerts": [], "linked_incidents": [], "attack_timeline": [], "change_overlap": [], "duplicates": [], "prioritised_events": [], "contiguous_logs": [], "sample_logs": [], "prefilter": self.withheld, "untrusted_fields": ["input_alert.raw", "input_alert.raw.evidence", "input_alert.raw.description", "contiguous_logs[].detail", "sample_logs[].detail"]}
            if input_flag.get("withhold"):
                meta["prefilter"]["withheld_counts"] = dict(Counter(x["item_type"] for x in self.withheld)); validate_context_package(base); return base
            candidate_rows = self._query(con, "SELECT * FROM v_alert_enriched WHERE replace(substr(created_at,1,16),'T',' ') BETWEEN datetime(replace(substr(?,1,16),'T',' '), '-24 hours') AND datetime(replace(substr(?,1,16),'T',' '), '+24 hours') AND alert_id <> ?", (normal["created_at"], normal["created_at"], normal["alert_id"]))
            source_entities = {(x["entity_type"], x["entity_value"]) for x in normal["entities"]}
            scored = []
            for row in candidate_rows:
                c = self._enrich_alert(row, con); score, parts = self._similar_score(normal, c, source_entities, c["entities_set"]); c["S_final"] = score * (0.75 + 0.25 * max(0.0, 1 - abs((_parse_time(c["created_at"]) - (_parse_time(raw.get("created_at")) or _parse_time(c["created_at"]))).total_seconds()) / 86400)); c["component_scores"] = parts; c["prefilter_flag"] = self._flag(c, "similar_alert"); scored.append(c)
            scored.sort(key=lambda x: (-x["S_final"], abs((_parse_time(x["created_at"]) - (_parse_time(raw.get("created_at")) or _parse_time(x["created_at"]))).total_seconds()), x["alert_id"]))
            for c in scored:
                if c["S_final"] < self.config.similar_min_score or c["prefilter_flag"].get("withhold"): continue
                c.pop("entities_set", None); c.pop("change_overlap", None); c.pop("is_duplicate", None); base["similar_alerts"].append({k: v for k, v in c.items() if k not in {"users", "hosts", "contexts", "incident_ids"}})
                if len(base["similar_alerts"]) >= self.config.similar_top_n: break
            ids = [normal["alert_id"]] + [x["alert_id"] for x in base["similar_alerts"]]
            placeholders = ",".join("?" for _ in ids)
            events = self._query(con, f"SELECT bae.alert_id, bae.event_id, bae.in_dim_log, l.* FROM bridge_alert_event bae LEFT JOIN dim_log l ON l.event_id=bae.event_id WHERE bae.alert_id IN ({placeholders}) ORDER BY bae.alert_id, bae.event_id", tuple(ids))
            for e in events:
                item = dict(e); item["missing"] = not bool(e["in_dim_log"] and e["timestamp"]); item["prefilter_flag"] = self._flag(item, "log")
                if item["prefilter_flag"].get("withhold"): continue
                base["prioritised_events"].append(item)
            start = normal["created_at"]; keys = set(normal["users"] + normal["hosts"] + normal["contexts"] + normal["event_ids"])
            logs = self._query(con, "SELECT * FROM dim_log WHERE timestamp BETWEEN datetime(?, '-10 minutes') AND datetime(?, '+10 minutes') ORDER BY timestamp, event_id", (start, start)) if start else []
            for row in logs:
                item = self._log_item(row); item["sample_context"] = not bool(keys & {row["user_key"], row["hostname"], row["sha256"], row["ref_id"], row["customer_id"], row["dst"]} - {None})
                if item["prefilter_flag"].get("withhold"): continue
                (base["contiguous_logs"] if not item["sample_context"] else base["sample_logs"]).append(item)
            base["contiguous_logs"] = base["contiguous_logs"][: self.config.max_contiguous_logs]; base["sample_logs"] = base["sample_logs"][: self.config.max_sample_logs]
            base["prefilter"] = self.withheld; meta["prefilter"]["withheld_counts"] = dict(Counter(x["item_type"] for x in self.withheld)); meta["prefilter"]["guard_applied_count"] = self.guard_count
            base["input_alert"]["prefilter_flag"] = input_flag
            validate_context_package(base)
            return base

    def build_json(self, raw: dict[str, Any], *, indent: int = 2) -> str:
        return json.dumps(self.build(raw), ensure_ascii=False, indent=indent)


def database_sha256(path: str | Path) -> str:
    """Small test/helper utility proving execution did not alter the database."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_context_package(package: dict[str, Any]) -> None:
    """Validate every emitted package against the shipped JSON Schema."""
    schema_path = Path(__file__).resolve().parents[3] / "db" / "context_package.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(package), key=lambda error: list(error.path))
    if errors:
        raise ValueError("context package schema validation failed: " + "; ".join(error.message for error in errors))


def validate_llm_response(response: dict[str, Any]) -> None:
    """Validate a downstream response without writing it to the database."""
    schema_path = Path(__file__).resolve().parents[3] / "db" / "llm_response_schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(response)
