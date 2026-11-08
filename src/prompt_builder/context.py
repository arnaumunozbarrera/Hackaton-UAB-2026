"""Alert context at identification level, built from the dataset and the informative-log selection.

Why: the prompt must identify the alert, the affected systems and the informative logs so the LLM can query the
database for the rest. `ContextSource` is the seam for the future database-backed implementation: today the
context comes from docs/ plus `log_noise_discard`; tomorrow it can come from the database without touching the
builder.
"""

from __future__ import annotations

import csv
import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..log_noise_discard import FilterResult, run_filter
from ..log_noise_discard.loaders import load_alerts


@dataclass(frozen=True)
class AffectedAsset:
    hostname: str
    criticality: str
    business_service: str
    zone: str
    asset_type: str


@dataclass(frozen=True)
class AffectedService:
    name: str
    criticality: str
    assets: str
    owner: str


@dataclass(frozen=True)
class AffectedUser:
    user_key: str
    account_type: str
    privileged: bool
    vip: bool
    hr_event: str


@dataclass(frozen=True)
class InformativeLog:
    event_id: str
    source: str
    timestamp: str
    reason: str  # why it is informative: unexplained, free text or guard


@dataclass
class AlertContext:
    """Everything the prompt needs, as identifiers; details stay in the database."""

    alert_id: str
    created_at: str
    rule_id: str
    rule_name: str
    rule_severity: str
    source_product: str
    technique_id: str
    tactic: str
    runbook_id: str
    description: str
    evidence: str  # JSON, attacker-controllable
    hosts: list[AffectedAsset] = field(default_factory=list)
    services: list[AffectedService] = field(default_factory=list)
    unknown_hosts: list[str] = field(default_factory=list)
    users: list[AffectedUser] = field(default_factory=list)
    unknown_users: list[str] = field(default_factory=list)
    entities: dict[str, list[str]] = field(default_factory=dict)  # ips, domains, urls, files, customers...
    informative_logs: list[InformativeLog] = field(default_factory=list)
    set_aside: dict[str, list[str]] = field(default_factory=dict)  # stage -> event_ids
    explanations: dict[str, str] = field(default_factory=dict)  # event_id -> context reference (N4)


# Alerts whose target is a business service rather than a host or identity (no host entity in the alert).
PRODUCT_SERVICES: dict[str, tuple[str, ...]] = {
    "WAF": ("Tienda online y app",),
    "ECOM": ("Tienda online y app",),
    "AI_GATEWAY": ("Asistente de compra con IA «Vela»",),
}


class ContextSource(Protocol):
    def get(self, alert_id: str) -> AlertContext: ...


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _flatten(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [v for x in value.values() for v in _flatten(x)]
    if isinstance(value, list):
        return [v for x in value for v in _flatten(x)]
    return []


def _user_ids(value: Any) -> list[str]:
    """Identity values of the alert's users (upn/username), skipping aggregates such as '(12 cuentas)'."""
    items = value if isinstance(value, list) else [value] if value else []
    ids = [i.get("upn") or i.get("username") or "" if isinstance(i, dict) else str(i) for i in items]
    return [i for i in ids if i and not i.startswith("(")]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _user_key(value: str) -> str:
    return value.lower().split("\\")[-1].split("@")[0]


class DatasetContextSource:
    """Context from docs/ (alerts, inventory, users, HR) and the informative-log filter."""

    def __init__(
        self,
        data_dir: str | Path = "docs",
        filter_result: FilterResult | None = None,
        product_services: dict[str, tuple[str, ...]] | None = None,
    ) -> None:
        self.data = Path(data_dir)
        self.alerts = load_alerts(self.data)
        inv = self.data / "02_inventario"
        self.assets = {r["hostname"]: r for r in _read_csv(inv / "activos.csv")}
        self.users = {r["username"].lower(): r for r in _read_csv(inv / "usuarios.csv")}
        self.hr = {_user_key(r["usuario"]): r["tipo"] for r in _read_csv(inv / "eventos_rrhh.csv")}
        self.catalog = {r["rule_id"]: r for r in _read_csv(self.data / "01_contexto" / "catalogo_casos_de_uso.csv")}
        self.services = {r["servicio"]: r for r in _read_csv(inv / "servicios_negocio.csv")}
        self.product_services = PRODUCT_SERVICES if product_services is None else product_services
        self._filter = filter_result

    @property
    def filter_result(self) -> FilterResult:
        if self._filter is None:
            self._filter = run_filter(self.data)
        return self._filter

    def _hosts(self, names: list[str]) -> tuple[list[AffectedAsset], list[str]]:
        known, unknown = [], []
        for name in sorted(set(names)):
            a = self.assets.get(name)
            if a:
                known.append(AffectedAsset(name, a["criticality"], a["business_service"], a["zone"], a["type"]))
            else:
                unknown.append(name)
        return known, unknown

    def _services(self, product: str, hosts: list[AffectedAsset]) -> list[AffectedService]:
        names = set(self.product_services.get(product, ())) | {h.business_service for h in hosts}
        rows = [self.services[n] for n in sorted(names) if n in self.services]
        return [AffectedService(r["servicio"], r["criticidad"], r["activos"], r["responsable"]) for r in rows]

    def _users(self, names: list[str]) -> tuple[list[AffectedUser], list[str]]:
        known, unknown = [], []
        for key in sorted({_user_key(n) for n in names}):
            u = self.users.get(key)
            if u:
                flags = (u["privileged"] == "True", u["vip"] == "True")
                known.append(AffectedUser(key, u["account_type"], *flags, self.hr.get(key, "")))
            else:
                unknown.append(key)
        return known, unknown

    def _logs(self, alert: dict[str, Any]) -> tuple[list[InformativeLog], dict[str, list[str]], dict[str, str]]:
        fr, logs = self.filter_result, []
        for rec in fr.kept_for_alert(alert["alert_id"]):
            reason = "no explicado"
            if rec.event_id in fr.open_text_kept:
                reason = f"texto libre, {fr.open_text_kept[rec.event_id].reference}"
            elif rec.event_id in fr.guarded:
                reason = f"guarda {fr.guarded[rec.event_id].split('_')[0]}"
            logs.append(InformativeLog(rec.event_id, rec.source, str(rec.event.get("timestamp", "")), reason))
        set_aside: dict[str, list[str]] = {}
        for eid in sorted(set(alert.get("related_events") or [])):
            if eid in fr.discarded:
                set_aside.setdefault(fr.discarded[eid], []).append(eid)
        refs = {e: fr.explanations[e].reference for e in set_aside.get("N4", [])}
        return logs, set_aside, refs

    def get(self, alert_id: str) -> AlertContext:
        alert = self.alerts.get(alert_id)
        if alert is None:
            raise KeyError(f"unknown alert: {alert_id}")
        ent = alert.get("entities") or {}
        host_values = _flatten(ent.get("hosts"))
        hosts, unknown_hosts = self._hosts([h for h in host_values if not _is_ip(h)])
        users, unknown_users = self._users(_user_ids(ent.get("users")))
        others = {k: sorted(set(_flatten(v))) for k, v in ent.items() if k not in ("hosts", "users")}
        host_ips = [h for h in host_values if _is_ip(h)]
        if host_ips:
            others["ips"] = sorted(set(others.get("ips", [])) | set(host_ips))
        logs, set_aside, refs = self._logs(alert)
        mitre = alert.get("mitre") or {}
        return AlertContext(
            alert_id, alert["created_at"], alert["rule_id"], alert["rule_name"], alert["severity"],
            alert["source_product"], mitre.get("technique_id", ""), mitre.get("tactic", ""),
            alert.get("runbook") or self.catalog.get(alert["rule_id"], {}).get("runbook", ""),
            alert.get("description", ""), json.dumps(alert.get("evidence") or {}, ensure_ascii=False),
            hosts, self._services(alert["source_product"], hosts), unknown_hosts, users, unknown_users, others, logs, set_aside, refs,
        )  # fmt: skip
