"""Dataset backend for the read function `consultar_bd`, used until the database exists.

Why: the LLM loop must be the same with or without the database. This backend answers the catalogue functions
from docs/ (alerts, inventory, intelligence, runbooks, policy, logs) with the same parameters and the same kind
of rows the database queries will return, so switching to SQLite only means swapping the backend.
Activity queries stream the logs with a substring pre-filter (a few seconds per call on the full dataset).
"""

from __future__ import annotations

import csv
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from ..log_noise_discard.context import Context, load_context, parse_ts
from ..log_noise_discard.loaders import LOGS_DIR
from ..log_noise_discard.templates import SOURCES, normalise_identity
from ..prompt_builder import QUERIES, DatasetContextSource, PromptBuilder
from ..prompt_builder.policy import CRITICALITY_ORDER, most_critical

MAX_ROWS = 50
SCAN_CAP = 2000
UNAVAILABLE = [{"error": "consulta no disponible sin base de datos (modo dataset)"}]


def _first(*values: Any) -> Any:
    return next((v for v in values if v not in (None, "", [])), None)


def normalise_log(source: str, e: dict[str, Any]) -> dict[str, Any]:
    """Project a raw event onto the dim_log columns."""
    ident = e.get("userIdentity") or {}
    recipient = (e.get("recipients") or [None])[0] if source == "email" else None
    user = _first(
        e.get("user"), e.get("user_upn"), e.get("actor_upn"), e.get("subject"), ident.get("userName"), recipient
    )
    return {
        "event_id": e["event_id"], "source": source, "timestamp": e["timestamp"],
        "user_key": normalise_identity(user) if user else None, "customer_id": e.get("customer_id"),
        "hostname": _first(e.get("hostname"), e.get("client_host"), e.get("src_host")),
        "src_ip": _first(e.get("src_ip"), e.get("sourceIPAddress"), e.get("sender_ip")),
        "dst": _first(e.get("domain"), e.get("query"), e.get("destination"), e.get("url"), e.get("dst_ip"),
                      e.get("host"), e.get("eventName")),
        "action": _first(e.get("action"), e.get("event_type"), e.get("event"), e.get("operation"), e.get("statement_type")),
        "result": _first(e.get("result"), e.get("status"), e.get("rcode"), e.get("verdict"), e.get("errorCode")),
        "sha256": e.get("sha256"), "ref_id": _first(e.get("message_id"), e.get("session_id"), e.get("build_id")),
    }  # fmt: skip


SUMMARY = ("event_id", "source", "timestamp", "user_key", "hostname", "src_ip", "dst", "action", "result")


class DatasetToolBackend:
    """Answers `consultar_bd(consulta, parametros)` from the dataset."""

    def __init__(self, source: DatasetContextSource, builder: PromptBuilder) -> None:
        self.src, self.builder, self.data = source, builder, source.data
        self.ctx: Context = load_context(self.data)
        vulns_path = self.data / "02_inventario" / "vulnerabilidades.csv"
        with vulns_path.open(encoding="utf-8", newline="") as fh:
            self.vulns = list(csv.DictReader(fh))
        self.handlers: dict[str, Callable[..., list[dict[str, Any]]]] = {
            "runbook_text": self._runbook_text, "alert_enriched": self._alert_enriched,
            "alert_entities": self._alert_entities, "alert_events": self._alert_events, "log_detail": self._log_detail,
            "user_profile": self._user_profile, "asset_profile": self._asset_profile, "indicator": self._indicator,
            "change_overlap": self._change_overlap, "changes_in_window": self._changes_in_window,
            "duplicates": self._duplicates, "incident_links": lambda alert_id: UNAVAILABLE,
            "related_alerts": self._related_alerts, "severity_matrix": self._severity_matrix,
            "user_activity": lambda v, ws, we: self._activity("user_key", v, ws, we),
            "host_activity": lambda v, ws, we: self._activity("hostname", v, ws, we),
            "ip_activity": lambda v, ws, we: self._activity("src_ip", v, ws, we),
            "customer_activity": lambda v, ws, we: self._activity("customer_id", v, ws, we),
            "ref_activity": lambda v: self._activity("ref_id", v), "hash_activity": lambda v: self._activity("sha256", v),
            "dst_spread": self._dst_spread,
        }  # fmt: skip

    # ------------------------------------------------------------ entry point
    def execute(self, consulta: str, parametros: list[str], allowed: list[str] | None = None) -> list[dict[str, Any]]:
        """Same contract as prompt_builder.tools.execute, without a database."""
        if consulta not in QUERIES or (allowed is not None and consulta not in allowed):
            raise ValueError(f"consulta no permitida: {consulta}")
        expected = QUERIES[consulta].params
        if len(parametros) != len(expected):
            raise ValueError(f"{consulta}({', '.join(expected)}) espera {len(expected)} parámetros")
        return self.handlers[consulta](*[str(p) for p in parametros])[:MAX_ROWS]

    # ------------------------------------------------------------ alert and runbook
    def _alert(self, alert_id: str) -> dict[str, Any]:
        return self.src.alerts.get(alert_id) or {}

    def _runbook_text(self, rule_id: str) -> list[dict[str, Any]]:
        rb_id = self.src.catalog.get(rule_id, {}).get("runbook", "")
        rb = self.builder.runbooks.get(rb_id)
        if rb is None:
            return []
        checks = "\n".join(f"{i}. {c}" for i, c in enumerate(rb.checks, 1))
        return [
            {"runbook": rb_id, "runbook_checks": checks, "runbook_decision": "\n".join(f"- {d}" for d in rb.decisions)}
        ]

    def _alert_enriched(self, alert_id: str) -> list[dict[str, Any]]:
        if alert_id not in self.src.alerts:
            return []
        c = self.src.get(alert_id)
        user, host = (c.users[0] if c.users else None), (c.hosts[0] if c.hosts else None)
        crit = most_critical([h.criticality for h in c.hosts] + [s.criticality for s in c.services])
        return [{
            "created_at": c.created_at, "rule_id": c.rule_id, "rule_severity": c.rule_severity,
            "technique_id": c.technique_id, "user_key": user and user.user_key, "privileged": user and user.privileged,
            "vip": user and user.vip, "hr_event": user and user.hr_event, "hostname": host and host.hostname,
            "asset_criticality": crit, "business_service": host.business_service if host else
            (c.services[0].name if c.services else None),
            "matrix_base_severity": self.builder.policy.base_severity(c.rule_severity, crit or "Media"),
        }]  # fmt: skip

    def _alert_entities(self, alert_id: str) -> list[dict[str, Any]]:
        rows = []
        for kind, values in sorted((self._alert(alert_id).get("entities") or {}).items()):
            for v in values if isinstance(values, list) else [values]:
                value = v.get("upn") if isinstance(v, dict) and "upn" in v else v
                rows.append(
                    {"entity_type": kind, "entity_value": value if isinstance(value, str) else json.dumps(value)}
                )
        return rows

    def _record(self, event_id: str) -> Any:
        fr = self.src.filter_result
        return fr.kept.get(event_id) or getattr(fr, "discarded_records", {}).get(event_id)

    def _alert_events(self, alert_id: str) -> list[dict[str, Any]]:
        fr, rows = self.src.filter_result, []
        for eid in sorted(set(self._alert(alert_id).get("related_events") or [])):
            rec = self._record(eid)
            state = "informativo" if eid in fr.kept else f"apartado {fr.discarded.get(eid, '?')}"
            base = (
                {k: v for k, v in normalise_log(rec.source, dict(rec.event)).items() if k in SUMMARY}
                if rec
                else {"event_id": eid}
            )
            rows.append(base | {"estado": state})
        return rows

    def _log_detail(self, event_id: str) -> list[dict[str, Any]]:
        rec = self._record(event_id)
        if rec is None:
            return []
        return [{"source": rec.source, "timestamp": rec.event.get("timestamp"),
                 "detail": json.dumps(rec.event, ensure_ascii=False)}]  # fmt: skip

    # ------------------------------------------------------------ entities
    def _user_profile(self, user_key: str) -> list[dict[str, Any]]:
        u = self.src.users.get(normalise_identity(user_key))
        if not u:
            return []
        cols = ("account_type", "department", "title", "privileged", "vip", "status", "workstation")
        hr = [r for r in self.ctx.trips if r.user == normalise_identity(user_key)]
        return [{k: u[k] for k in cols} | {"hr_event": self.src.hr.get(normalise_identity(user_key)),
                                           "trips": [f"{t.start}..{t.end}" for t in hr]}]  # fmt: skip

    def _asset_profile(self, hostname: str) -> list[dict[str, Any]]:
        a = self.src.assets.get(hostname)
        if not a:
            return []
        vulns = [v for v in self.vulns if v["hostname"] == hostname and v["estado"] == "abierta"]
        cols = ("type", "criticality", "zone", "business_service", "internet_facing", "edr_installed")
        return [{k: a[k] for k in cols} | {"open_vuln_count": len(vulns),
                "cve_ids": "; ".join(f"{v['id']}:{v['producto']}:{v['severidad_cvss']}" for v in vulns)}]  # fmt: skip

    def _indicator(self, value: str) -> list[dict[str, Any]]:
        v = value.lower()
        ti, geo, sbx = self.ctx.ti.get(v), self.ctx.geo.get(value), self.ctx.sandbox.get(value)
        if not (ti or geo or sbx):
            return [{"reputation": None, "nota": "desconocido en TIP, GeoIP y sandbox (desconocido no es limpio)"}]
        row: dict[str, Any] = {}
        if ti:
            row |= {
                k: ti.get(k)
                for k in ("indicator_type", "reputation", "confidence", "malware_family", "tags", "last_seen")
            }
        if geo:
            row |= {k: geo.get(k) for k in ("country", "as_org", "is_tor", "is_vpn_provider", "is_hosting")}
        if sbx:
            row |= {"sandbox_verdict": sbx.get("verdict"), "sandbox_family": sbx.get("malware_family")}
        return [row]

    # ------------------------------------------------------------ changes, duplicates, related
    def _change_overlap(self, alert_id: str) -> list[dict[str, Any]]:
        alert = self._alert(alert_id)
        if not alert:
            return []
        ts, values = parse_ts(alert["created_at"]), [r["entity_value"].lower() for r in self._alert_entities(alert_id)]
        rows = []
        for ch in self.ctx.changes:
            if ch.covers(ts):
                text = f"{ch.title} {ch.detail} {ch.scope}".lower()
                match = any(len(v) > 3 and v in text for v in values)
                rows.append(
                    {"change_id": ch.id, "change_title": ch.title, "change_scope": ch.scope, "entity_match": match}
                )
        return rows

    def _changes_in_window(self, window_end: str, window_start: str) -> list[dict[str, Any]]:
        end, start = parse_ts(window_end), parse_ts(window_start)
        return [
            {"change_id": c.id, "change_title": c.title, "change_start": c.start.isoformat(), "change_end": c.end.isoformat(),
             "change_scope": c.scope, "change_detail": c.detail}
            for c in self.ctx.changes if c.start <= end and c.end >= start
        ]  # fmt: skip

    def _entity_key(self, alert: dict[str, Any]) -> str:
        return json.dumps(alert.get("entities") or {}, sort_keys=True, ensure_ascii=False)

    def _duplicates(self, alert_id: str) -> list[dict[str, Any]]:
        a = self._alert(alert_id)
        if not a:
            return []
        key = (a["rule_id"], a["created_at"][:10], self._entity_key(a))
        same = sorted(x["alert_id"] for x in self.src.alerts.values()
                      if (x["rule_id"], x["created_at"][:10], self._entity_key(x)) == key)  # fmt: skip
        if len(same) < 2:
            return []
        times = sorted(self.src.alerts[i]["created_at"] for i in same)
        return [{"n": len(same), "first_seen": times[0], "last_seen": times[-1], "alert_ids": ",".join(same)}]

    def _related_alerts(
        self, entity_value: str, window_start: str, window_end: str, alert_id: str
    ) -> list[dict[str, Any]]:
        needle, rows = entity_value.lower(), []
        for aid, a in sorted(self.src.alerts.items()):
            if aid == alert_id or not (window_start <= a["created_at"] <= window_end):
                continue
            if needle in json.dumps(a.get("entities") or {}, ensure_ascii=False).lower():
                rows.append(
                    {
                        "alert_id": aid,
                        "rule_id": a["rule_id"],
                        "rule_severity": a["severity"],
                        "created_at": a["created_at"],
                    }
                )
        return rows

    def _severity_matrix(self, rule_severity: str) -> list[dict[str, Any]]:
        m = self.builder.policy.matrix
        return [
            {"criticality": c, "base_severity": m[(rule_severity, c)]}
            for c in CRITICALITY_ORDER
            if (rule_severity, c) in m
        ]

    # ------------------------------------------------------------ log scans
    def _scan(self, needle: str) -> Iterator[dict[str, Any]]:
        """Stream all logs, parsing only lines that contain the needle."""
        for source, spec in SOURCES.items():
            path: Path = self.data / LOGS_DIR / spec.file
            with path.open(encoding="utf-8", newline="") as fh:
                header = next(csv.reader([fh.readline()])) if spec.fmt == "csv" else None
                for line in fh:
                    if needle not in line:
                        continue
                    event = dict(zip(header, next(csv.reader([line])), strict=False)) if header else json.loads(line)
                    yield normalise_log(source, event)

    def _activity(self, column: str, value: str, start: str = "", end: str = "~") -> list[dict[str, Any]]:
        target = normalise_identity(value) if column == "user_key" else value
        needle = target if column != "user_key" else target.split("@")[0]
        rows = []
        for row in self._scan(needle):
            if row[column] == target and start <= row["timestamp"] <= end:
                rows.append({k: row[k] for k in SUMMARY})
                if len(rows) >= SCAN_CAP:
                    break
        return sorted(rows, key=lambda r: r["timestamp"])

    def _dst_spread(self, indicator: str) -> list[dict[str, Any]]:
        hosts, times, events = set(), [], 0
        for row in self._scan(indicator):
            if row["dst"] == indicator:
                events += 1
                hosts.add(row["hostname"])
                times.append(row["timestamp"])
        if not events:
            return [{"hosts": 0, "events": 0}]
        return [{"hosts": len(hosts - {None}), "events": events, "first_seen": min(times), "last_seen": max(times)}]
