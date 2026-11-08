"""Stage N4: logs whose activity is already explained by authoritative context.

Why: an approved change, a documented company rule, a TIP/GeoIP label, a sandbox verdict or an HR record can
fully describe a log; the runbook then closes the alert. Such a log only needs a reference to its context
record. Three safety rules keep look-alike attacks informative:

- every condition must match (time window, scope and actor), not just a known entity;
- G1: a log containing a malicious/suspicious TIP indicator is never discarded;
- G2: a log of an entity with an unexplained high/critical alert within +-24 h is never discarded;
- open text: an explained log that carries a free-text field (subject, description, command line, prompt,
  file name, message...) stays informative, because that text can be written by the attacker.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from .config import NoiseFilterConfig
from .context import MADRID, RELAY_ORG, Context, parse_ts
from .stages import LogRecord
from .templates import normalise_identity

OT_ZONE = "LOGISTICS-OT"
OT_AUTHORISED_HOSTS = ("ENG-WS01", "WMS01")  # empresa_tarvia.md
LOGISOFT_USER = "ext.logisoft"  # empresa_tarvia.md: Mon-Fri 08-18, only WMS01


@dataclass(frozen=True)
class Explanation:
    category: str
    reference: str


@dataclass
class N4Outcome:
    discarded: dict[str, Explanation] = field(default_factory=dict)
    open_text_kept: dict[str, Explanation] = field(default_factory=dict)
    guarded: dict[str, str] = field(default_factory=dict)


def _strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj.lower()
    elif isinstance(obj, Mapping):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _dumps(event: Mapping[str, Any]) -> str:
    return json.dumps(event, ensure_ascii=False).lower()


# ---------------------------------------------------------------- A: approved changes (calendario_cambios)
def _change(ctx: Context, ts: datetime, select: Callable[[Any], bool]) -> str | None:
    for ch in ctx.changes:
        if select(ch) and ch.covers(ts):
            return ch.id
    return None


def _pentest(r: LogRecord, ts: datetime, ctx: Context) -> str | None:
    if r.source not in ("waf", "ecom_auth"):
        return None
    ip = r.event["src_ip"]

    def select(ch: Any) -> bool:
        m = re.search(r"IPs origen (\d+\.\d+\.\d+\.)(\d+)-(\d+)", ch.detail)
        return bool(m) and ip.startswith(m[1]) and int(m[2]) <= int(ip.rsplit(".", 1)[1]) <= int(m[3])

    return _change(ctx, ts, select)


def _scanner(r: LogRecord, ts: datetime, ctx: Context) -> str | None:
    e = r.event
    if r.source != "firewall" or e["src_ip"] != ctx.asset_ip("NESSUS01") or e["zone_dst"] == OT_ZONE:
        return None
    return _change(ctx, ts, lambda ch: "NESSUS01" in ch.detail)


def _psexec(r: LogRecord, ts: datetime, ctx: Context) -> str | None:
    e = r.event
    if r.source != "edr_events" or not normalise_identity(e.get("user", "")).startswith("adm."):
        return None
    hosts = lambda ch: [h.strip() for h in ch.scope.split(",")]  # noqa: E731
    return _change(ctx, ts, lambda ch: "PsExec" in ch.detail and e.get("hostname") in hosts(ch))


def _ot_maintenance(r: LogRecord, ts: datetime, ctx: Context) -> str | None:
    e = r.event
    if r.source != "firewall" or e["src_ip"] != ctx.asset_ip("JUMP01"):
        return None

    def select(ch: Any) -> bool:
        m = re.search(r"regla temporal (\S+)", ch.detail)
        return bool(m) and m[1] in e["rule"]

    return _change(ctx, ts, select)


def _vpn_certificates(r: LogRecord, ts: datetime, ctx: Context) -> str | None:
    if r.source != "vpn" or r.event["action"] != "disconnect":
        return None
    return _change(ctx, ts, lambda ch: "VPN-GW01" in ch.scope)


def _logisoft_change(r: LogRecord, ts: datetime, ctx: Context) -> str | None:
    e = r.event
    vpn = r.source == "vpn" and e.get("user") == LOGISOFT_USER
    fw = r.source == "firewall" and e["rule"] == "VPN-EXT-LOGISOFT" and e["dst_ip"] == ctx.asset_ip("WMS01")
    return _change(ctx, ts, lambda ch: LOGISOFT_USER in ch.detail) if vpn or fw else None


def _backup_operators(r: LogRecord, ts: datetime, ctx: Context) -> str | None:
    if r.source != "ad_events" or "backup operators" not in _dumps(r.event):
        return None
    return _change(ctx, ts, lambda ch: "Backup Operators" in ch.title)


def _edr_update(r: LogRecord, ts: datetime, ctx: Context) -> str | None:
    e = r.event
    is_server = ctx.assets.get(e.get("hostname") or "", {}).get("type", "").startswith("Servidor")
    if r.source != "edr_events" or e.get("event_type") != "agent_status" or not is_server:
        return None
    return _change(ctx, ts, lambda ch: "agente EDR" in ch.title)


def _sccm(r: LogRecord, ts: datetime, ctx: Context) -> str | None:
    e = r.event
    if r.source != "edr_events" or (e.get("parent_name") or "").lower() != "ccmexec.exe":
        return None
    if (e.get("process_name") or "").lower() != "powershell.exe" or "win32_product" not in _dumps(
        e.get("details") or {}
    ):
        return None

    def select(ch: Any) -> bool:
        m = re.search(r"(\d{2}):00-(\d{2}):00", ch.detail)
        return "svc_sccm" in ch.detail and bool(m) and int(m[1]) <= ts.astimezone(MADRID).hour < int(m[2])

    return _change(ctx, ts, select)


def _authorised_flow(r: LogRecord, ts: datetime, ctx: Context) -> str | None:
    if r.source not in ("email", "dlp"):
        return None
    text = _dumps(r.event)

    def select(ch: Any) -> bool:
        m = re.search(r"Destino (\S+@\S+?);", ch.detail)
        return ch.id.startswith("FLUJO") and bool(m) and m[1].lower() in text

    return _change(ctx, ts, select)


CHANGE_MATCHERS = (
    _pentest, _scanner, _psexec, _ot_maintenance, _vpn_certificates, _logisoft_change,
    _backup_operators, _edr_update, _sccm, _authorised_flow,
)  # fmt: skip


# ---------------------------------------------------------------- B: permanent company rules (empresa_tarvia.md)
def _company_rule(r: LogRecord, ts: datetime, ctx: Context) -> str | None:
    e, local = r.event, ts.astimezone(MADRID)
    if r.source == "firewall" and e["zone_dst"] == OT_ZONE:
        if e["src_ip"] in {ctx.asset_ip(h) for h in OT_AUTHORISED_HOSTS}:
            return "ENG-WS01/WMS01 -> OT autorizado"
    if r.source == "vpn" and e.get("user") == LOGISOFT_USER and local.weekday() < 5 and 8 <= local.hour < 18:
        return "Logisoft L-V 8-18 h"
    actor = e.get("user") or e.get("subject") or e.get("user_upn") or ""
    host = e.get("hostname") or e.get("src_host")
    if r.source in ("edr_events", "ad_events") and normalise_identity(actor).startswith("adm.") and host == "JUMP01":
        return "adm.* desde JUMP01"
    return None


# ---------------------------------------------------------------- C/D/E: known IP-domain, sandbox, DLP
def _domain_in(domain: str, domains: set[str]) -> bool:
    d = (domain or "").lower()
    return any(d == x or d.endswith("." + x) for x in domains)


def _known_ip_domain(r: LogRecord, ctx: Context) -> str | None:
    e = r.event
    if (
        r.source == "waf"
        and ctx.org(e["src_ip"]).startswith("Hosting (escáner de Internet")
        and e["action"] == "blocked"
    ):
        if e["src_ip"] not in ctx.waf_ok_ips and e["src_ip"] not in ctx.ecom_ok_ips:
            return "Escáner de Internet bloqueado sin actividad posterior (GeoIP, RB-05)"
    if r.source == "proxy" and ctx.org(e["dst_ip"]).startswith("Agente de"):
        return "Agente conocido (GeoIP, RB-09)"
    domain = e.get("domain") if r.source == "proxy" else e.get("query") if r.source == "dns" else None
    if domain and _domain_in(domain, ctx.benign_domains):
        return "Dominio benigno del TIP (RB-09)"
    return None


def _sandbox(r: LogRecord, ctx: Context) -> str | None:
    e = r.event
    if r.source != "edr_events" or e.get("event_type") != "detection":
        return None
    blocked = str((e.get("details") or {}).get("action", "")).lower() in ("blocked", "quarantined")
    clean = ctx.sandbox.get(e.get("sha256") or "", {}).get("verdict") == "clean"
    return "Sandbox clean y bloqueado (RB-02)" if blocked and clean else None


def _dlp(r: LogRecord, ctx: Context) -> str | None:
    e = r.event
    if r.source == "dlp" and not e["matches"] and e["action"] == "audit":
        if normalise_identity(e["user"]) not in ctx.leavers:
            return "DLP sin datos sensibles (RB-04)"
    return None


def explain_log(r: LogRecord, ctx: Context) -> Explanation | None:
    """Per-log explanation (categories A-E), or None."""
    ts = parse_ts(r.event["timestamp"])
    for matcher in CHANGE_MATCHERS:
        ref = matcher(r, ts, ctx)
        if ref:
            return Explanation("A_cambio_aprobado", ref)
    ref = _company_rule(r, ts, ctx)
    if ref:
        return Explanation("B_regla_empresa", ref)
    for category, fn in (("C_ip_dominio_conocido", _known_ip_domain), ("D_sandbox", _sandbox), ("E_dlp", _dlp)):
        ref = fn(r, ctx)
        if ref:
            return Explanation(category, ref)
    return None


# ---------------------------------------------------------------- F: impossible travel (alert level, RB-03)
def _travel_explained(signins: list[LogRecord], ctx: Context) -> Explanation | None:
    for r in signins:
        e = r.event
        if ctx.org(e["src_ip"]).startswith(RELAY_ORG) and e["result"] == "success":
            if e["device_id"] in ctx.known_devices[e["user_upn"]]:
                return Explanation("F_viaje_dispositivo", "Private Relay con dispositivo conocido (RB-03)")
        day, user = parse_ts(e["timestamp"]).date(), normalise_identity(e["user_upn"])
        if e["country"] != "ES" and any(t.user == user and t.start <= day <= t.end for t in ctx.trips):
            return Explanation("F_viaje_dispositivo", "Viaje notificado en RRHH (RB-03)")
    return None


# ---------------------------------------------------------------- guards and open text
def _has_bad_indicator(event: Mapping[str, Any], bad: set[str]) -> bool:
    long_bad = [b for b in bad if len(b) > 6 and "." in b]
    return any(s in bad or any(b in s for b in long_bad) for s in _strings(event))


def _chain_keys(
    alerts: Mapping[str, Mapping[str, Any]], unexplained: Iterable[str], severity: Mapping[str, str]
) -> set[tuple[str, date]]:
    keys: set[tuple[str, date]] = set()
    for aid in unexplained:
        alert = alerts[aid]
        if severity.get(alert["rule_id"]) not in ("high", "critical"):
            continue
        day = parse_ts(alert["created_at"]).date()
        for value in _strings(alert.get("entities", {})):
            keys.update((normalise_identity(value), day + timedelta(days=k)) for k in (-1, 0, 1))
    return keys


def has_open_text(r: LogRecord, cfg: NoiseFilterConfig) -> bool:
    """True when any configured free-text field of the log is non-empty."""
    for path in cfg.open_text_fields.get(r.source, ()):
        value: Any = r.event
        for part in path.split("."):
            value = value.get(part) if isinstance(value, Mapping) else None
        if isinstance(value, str) and value.strip():
            return True
    return False


# ---------------------------------------------------------------- stage
def _explain_all(
    candidates: list[str], records: Mapping[str, LogRecord], alerts: Mapping[str, Mapping[str, Any]], ctx: Context
) -> dict[str, Explanation]:
    found = {eid: exp for eid in candidates if (exp := explain_log(records[eid], ctx))}
    cand = set(candidates)
    for aid in sorted(alerts):
        if alerts[aid]["rule_id"] != "UC-IDP-001":
            continue
        eids = sorted(set(alerts[aid].get("related_events") or []) & cand)
        exp = _travel_explained([records[e] for e in eids if records[e].source == "idp_signins"], ctx)
        if exp:
            for eid in eids:
                found.setdefault(eid, exp)
    return found


def stage_n4(
    candidates: Iterable[str],
    records: Mapping[str, LogRecord],
    alerts: Mapping[str, Mapping[str, Any]],
    severity: Mapping[str, str],
    ctx: Context,
    cfg: NoiseFilterConfig,
) -> N4Outcome:
    """Split candidates into explained-and-discarded, explained-but-open-text (kept) and guarded (kept)."""
    ordered = sorted(candidates)
    found = _explain_all(ordered, records, alerts, ctx)
    cand = set(ordered)
    unexplained = [
        aid
        for aid, a in alerts.items()
        if (cited := set(a.get("related_events") or []) & cand) and not cited <= found.keys()
    ]
    chain, bad, out = _chain_keys(alerts, sorted(unexplained), severity), ctx.bad_indicators, N4Outcome()
    for eid in sorted(found):
        r = records[eid]
        if _has_bad_indicator(r.event, bad):
            out.guarded[eid] = "G1_ioc_tip"
        elif (normalise_identity(r.entity), parse_ts(r.event["timestamp"]).date()) in chain:
            out.guarded[eid] = "G2_cadena_alerta_high"
        elif has_open_text(r, cfg):
            out.open_text_kept[eid] = found[eid]
        else:
            out.discarded[eid] = found[eid]
    return out
