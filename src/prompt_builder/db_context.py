"""Database-backed `ContextSource`: the same AlertContext as `DatasetContextSource`, read from SQLite.

Why: at run time the database is the single source of truth (alerts arrive from the SOC API through
`database.sync`). Alerts are rebuilt in the JSONL shape the builder already understands, inventory comes from
the inventory tables and the informative-log selection from `alert_log_selection` (persisted by
`triage_flow.selection`). The prompt therefore does not change between dataset and database mode.
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .context import PRODUCT_SERVICES, DatasetContextSource


@dataclass(frozen=True)
class StoredExplanation:
    category: str
    reference: str


@dataclass(frozen=True)
class StoredRecord:
    """Minimal LogRecord: what the context and the server read from a selected log."""

    event_id: str
    source: str
    event: dict[str, Any]


@dataclass
class StoredSelection:
    """FilterResult-compatible view over `alert_log_selection`."""

    kept: dict[str, StoredRecord] = field(default_factory=dict)
    discarded: dict[str, str] = field(default_factory=dict)
    alert_events: dict[str, list[str]] = field(default_factory=dict)
    explanations: dict[str, StoredExplanation] = field(default_factory=dict)
    open_text_kept: dict[str, StoredExplanation] = field(default_factory=dict)
    guarded: dict[str, str] = field(default_factory=dict)
    discarded_records: dict[str, StoredRecord] = field(default_factory=dict)
    states: dict[str, dict[str, str]] = field(default_factory=dict)  # alert_id -> event_id -> state

    def kept_for_alert(self, alert_id: str) -> list[StoredRecord]:
        return [self.kept[e] for e in self.alert_events.get(alert_id, []) if e in self.kept]

    @classmethod
    def load(cls, conn: sqlite3.Connection) -> StoredSelection:
        sel = cls()
        rows = conn.execute(
            "SELECT alert_id, event_id, source, timestamp, state, reason, reference FROM alert_log_selection "
            "ORDER BY alert_id, event_id"
        )
        for alert_id, eid, source, ts, state, reason, ref in rows:
            sel.states.setdefault(alert_id, {})[eid] = state
            record = StoredRecord(eid, source or "", {"timestamp": ts or ""})
            reason = reason or ""
            if state in ("kept", "unfiltered"):
                sel.kept[eid] = record
                sel.alert_events.setdefault(alert_id, []).append(eid)
                if reason.startswith("open_text:"):
                    sel.open_text_kept[eid] = StoredExplanation(reason.split(":", 1)[1], ref or "")
                elif reason.startswith("guard:"):
                    sel.guarded[eid] = reason.split(":", 1)[1]
            else:
                sel.discarded[eid] = state
                sel.discarded_records[eid] = record
                if state == "N4":
                    sel.explanations[eid] = StoredExplanation(reason.split(":", 1)[-1], ref or "")
        return sel


def _bool_text(value: Any) -> str:
    return "True" if value in (1, True, "1", "True", "true") else "False"


class DbContextSource(DatasetContextSource):
    """AlertContext from the database. Reuses the dataset logic over data loaded from SQLite."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        product_services: dict[str, tuple[str, ...]] | None = None,
        data_dir: str | Path = "docs",
    ) -> None:
        self.conn = conn
        self.data = Path(data_dir)  # policy, runbooks and schema files only
        self.product_services = PRODUCT_SERVICES if product_services is None else product_services
        self._filter: StoredSelection | None = None
        self.reload()

    # ------------------------------------------------------------ loading
    def reload(self) -> None:
        """Re-read alerts, inventory and selection (call after ingestion or filtering)."""
        c = self.conn
        self.assets = {
            h: {"criticality": cr, "business_service": bs, "zone": z, "type": t, "ip": ip}
            for h, cr, bs, z, t, ip in c.execute(
                "SELECT hostname, criticality, business_service, zone_id, type, ip FROM assets"
            )
        }
        self.users = {
            key: {"account_type": at, "privileged": _bool_text(p), "vip": _bool_text(v), "upn": upn}
            for key, at, p, v, upn in c.execute("SELECT lower(username), account_type, privileged, vip, upn FROM users")
        }
        self.hr = {k: e for k, e in c.execute("SELECT user_key, hr_event FROM dim_user WHERE hr_event IS NOT NULL")}
        self.catalog = {
            r: {"runbook": rb, "rule_name": n, "source_product": p}
            for r, rb, n, p in c.execute("SELECT rule_id, runbook_id, name, source_product FROM detection_rules")
        }
        self.services = {
            n: {"servicio": n, "criticidad": cr, "activos": a, "responsable": o}
            for n, cr, a, o in c.execute(
                "SELECT name, criticality, asset_references, owner_role FROM business_services"
            )
        }
        self.alerts = self._load_alerts()
        self._filter = None

    def _load_alerts(self) -> dict[str, dict[str, Any]]:
        c = self.conn
        ent: dict[str, dict[str, Any]] = defaultdict(dict)

        def push(alert_id: str, key: str, value: Any) -> None:
            ent[alert_id].setdefault(key, []).append(value)

        for aid, upn, name in c.execute(
            "SELECT x.alert_id, u.upn, u.display_name FROM alert_users x JOIN users u ON u.user_id = x.user_id "
            "ORDER BY x.alert_id, u.upn"
        ):
            push(aid, "users", {"upn": upn, "display_name": name})
        for aid, host, ip in c.execute(
            "SELECT x.alert_id, a.hostname, a.ip FROM alert_assets x JOIN assets a ON a.asset_id = x.asset_id "
            "ORDER BY x.alert_id, a.hostname"
        ):
            push(aid, "hosts", {"hostname": host, "ip": ip})
        kinds = {"ip": "ips", "domain": "domains", "url": "urls"}
        for aid, kind, value in c.execute(
            "SELECT alert_id, indicator_type, value FROM alert_indicators ORDER BY rowid"
        ):
            push(aid, kinds.get(kind, kind), value)
        for aid, name, sha, path in c.execute(
            "SELECT alert_id, file_name, sha256, path FROM alert_files ORDER BY alert_id, position"
        ):
            push(aid, "files", {k: v for k, v in (("name", name), ("sha256", sha), ("path", path)) if v is not None})
        for aid, name, parent, cmd, pid in c.execute(
            "SELECT alert_id, name, parent_name, command_line, pid FROM alert_processes ORDER BY alert_id, position"
        ):
            push(aid, "processes", {k: v for k, v in (("name", name), ("parent", parent), ("command_line", cmd),
                                                      ("pid", pid)) if v is not None})  # fmt: skip
        for aid, cust, role in c.execute(
            "SELECT alert_id, customer_id, role FROM alert_customers ORDER BY alert_id, position"
        ):
            push(aid, "customers", {k: v for k, v in (("customer_id", cust), ("role", role)) if v is not None})
        for aid, account, identity, bucket, key, new_user in c.execute(
            "SELECT alert_id, cloud_account, identity, bucket, access_key, new_user FROM alert_cloud"
        ):
            ent[aid]["cloud"] = {k: v for k, v in (("account", account), ("identity", identity), ("bucket", bucket),
                                                   ("access_key", key), ("new_user", new_user)) if v is not None}  # fmt: skip
        for aid, session in c.execute("SELECT alert_id, session_id FROM alert_ai_sessions"):
            ent[aid]["ai_session"] = session
        events: dict[str, list[str]] = defaultdict(list)
        for aid, eid in c.execute("SELECT alert_id, event_id FROM alert_events ORDER BY alert_id, position"):
            if eid:
                events[aid].append(eid)
        alerts: dict[str, dict[str, Any]] = {}
        for row in c.execute(
            "SELECT a.alert_id, a.created_at, a.rule_id, a.severity, a.status, a.description, a.evidence_json, "
            "a.reported_user_count, r.name, r.source_product, r.tactic, r.technique_id, r.technique_name, r.runbook_id "
            "FROM alerts a JOIN detection_rules r ON r.rule_id = a.rule_id ORDER BY a.alert_id"
        ):
            aid, created, rule, sev, status, desc, evidence, count, name, product, tactic, tid, tname, rb = row
            entities = ent.get(aid, {})
            if count:
                entities.setdefault("users", []).append({"upn": f"({count} cuentas)"})
            alerts[aid] = {
                "alert_id": aid, "created_at": created, "source_product": product, "rule_id": rule,
                "rule_name": name, "severity": sev, "status": status,
                "mitre": {"tactic": tactic, "technique_id": tid, "technique": tname}, "description": desc or "",
                "entities": entities, "evidence": json.loads(evidence) if evidence else {},
                "related_events": events.get(aid, []), "runbook": rb,
            }  # fmt: skip
        return alerts

    # ------------------------------------------------------------ selection
    @property
    def filter_result(self) -> StoredSelection:  # type: ignore[override]
        if self._filter is None:
            self._filter = StoredSelection.load(self.conn)
        return self._filter

    def get(self, alert_id: str):  # noqa: ANN201 - same return type as the parent
        ctx = super().get(alert_id)
        ctx.similar_alerts = self.similar_alerts(alert_id)
        return ctx

    def similar_alerts(self, alert_id: str) -> list[dict[str, Any]]:
        """Resolved alerts close to this one in the embedding space (empty when no index or no history)."""
        try:
            from ..triage_flow.similarity import similar_resolved
        except ImportError:  # pragma: no cover
            return []
        return similar_resolved(self.conn, alert_id)
