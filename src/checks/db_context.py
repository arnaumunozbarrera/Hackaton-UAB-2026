"""Authoritative context for the basic checks, read from the database instead of `docs/`.

Why: `src.log_noise_discard.context.Context` is what the N4 rules consult (TIP, GeoIP, sandbox, assets, change
calendar, HR trips and leavers). The database holds the same reference data, so the rules can run per alert in
the live workflow.

The N4 rules also need a few facts about *other* logs ("did this scanner IP ever get a 2xx?", "which devices does
this user normally sign in from?"). A context-only database only holds the logs of alerts already ingested, so a
missing fact there does not prove absence. `ApiFacts` additionally asks the SOC API log search (read-only) so that
"never" really means never; without an API the checks fall back to the database (`DbFacts`). Facts only ever make
the checks keep more alerts, never close more: an IP with a success is no longer an unanswered scanner.
"""

from __future__ import annotations

import copy
import ipaddress
import re
import sqlite3
from collections import defaultdict
from datetime import date, timedelta
from typing import Any, Protocol

from ..log_noise_discard.context import RELAY_ORG, Change, Context, Trip, parse_ts
from ..log_noise_discard.templates import normalise_identity


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    cur = conn.execute(sql, params)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]


def _trip(details: str, effective: str, upn: str) -> Trip:
    m = re.search(r"del (\d{2})/(\d{2}) al (\d{2})/(\d{2})", details or "")
    start = date(2026, int(m[2]), int(m[1])) if m else date.fromisoformat(effective)
    end = date(2026, int(m[4]), int(m[3])) if m else start + timedelta(days=7)
    return Trip(normalise_identity(upn), start, end)


def load_context(conn: sqlite3.Connection) -> Context:
    """Reference data used by the N4 rules, built from the inventory and intelligence tables."""
    zones = []
    for z in _rows(conn, "SELECT zone_id, cidr FROM network_zones WHERE cidr IS NOT NULL"):
        try:
            zones.append((ipaddress.ip_network(z["cidr"]), z["zone_id"]))
        except ValueError:
            continue
    hr = _rows(
        conn,
        "SELECT h.event_type, h.details, h.effective_date, u.upn FROM hr_events h JOIN users u ON u.user_id = h.user_id",
    )
    return Context(
        geo={
            g["ip"]: {k: "" if v is None else str(v) for k, v in g.items()} for g in _rows(conn, "SELECT * FROM geoip")
        },
        ti={
            t["value"].lower(): {**t, "note": t["note"] or ""}
            for t in _rows(conn, "SELECT value, indicator_type, reputation, confidence, note FROM threat_intelligence")
        },
        sandbox={s["sha256"]: s for s in _rows(conn, "SELECT sha256, verdict, score FROM sandbox_reports")},
        assets={
            a["hostname"]: {**{k: "" if v is None else str(v) for k, v in a.items()}, "zone": a["zone_id"] or ""}
            for a in _rows(conn, "SELECT hostname, ip, type, zone_id, criticality FROM assets")
        },
        zones=zones,
        changes=[
            Change(
                c["change_id"],
                c["title"],
                parse_ts(c["start_at"]),
                parse_ts(c["end_at"]),
                c["details"] or "",
                c["scope"] or "",
            )
            for c in _rows(conn, "SELECT change_id, title, start_at, end_at, details, scope FROM changes")
        ],  # fmt: skip
        trips=[_trip(h["details"], h["effective_date"], h["upn"]) for h in hr if h["event_type"] == "viaje"],
        leavers={normalise_identity(h["upn"]) for h in hr if h["event_type"].startswith("baja")},
    )


class Facts(Protocol):
    """Facts about logs outside the alert that N4 conditions depend on."""

    def web_success(self, ip: str) -> bool: ...  # WAF 2xx/3xx allowed, or e-commerce login success

    def known_devices(self, upn: str) -> set[str]: ...  # devices seen on sign-ins not via Private Relay


class DbFacts:
    """Facts from the logs stored in the database (complete only for a full build)."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def web_success(self, ip: str) -> bool:
        waf = self.conn.execute(
            "SELECT 1 FROM waf_logs WHERE src_ip = ? AND action = 'allowed' AND http_status BETWEEN 200 AND 399 LIMIT 1",
            (ip,),
        ).fetchone()
        ecom = self.conn.execute(
            "SELECT 1 FROM ecom_auth_logs WHERE src_ip = ? AND result = 'success' LIMIT 1", (ip,)
        ).fetchone()
        return bool(waf or ecom)

    def known_devices(self, upn: str) -> set[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT s.device_id FROM idp_signins_logs s JOIN users u ON u.user_id = s.user_id "
            "LEFT JOIN geoip g ON g.ip = s.src_ip WHERE u.upn = ? COLLATE NOCASE AND s.device_id IS NOT NULL "
            "AND COALESCE(g.as_org, '') NOT LIKE ?",
            (upn, RELAY_ORG + "%"),
        )
        return {r[0] for r in rows}


class ApiFacts:
    """Database facts plus the SOC API log search (GET /logs/{source}?q=...), so absence is checked on all logs."""

    def __init__(self, api: Any, db: DbFacts, limit: int = 2000):
        self.api, self.db, self.limit = api, db, limit

    def _search(self, source: str, q: str) -> list[dict[str, Any]]:
        return list(self.api.search_logs(source, q, limit=self.limit))

    def web_success(self, ip: str) -> bool:
        if self.db.web_success(ip):
            return True
        waf = any(
            e.get("src_ip") == ip and e.get("action") == "allowed" and str(e.get("status"))[:1] in "23"
            for e in self._search("waf", ip)
        )
        return waf or any(e.get("src_ip") == ip and e.get("result") == "success" for e in self._search("ecom_auth", ip))

    def known_devices(self, upn: str) -> set[str]:
        devices = self.db.known_devices(upn)
        geo = {
            r[0]: r[1] or ""
            for r in self.db.conn.execute("SELECT ip, as_org FROM geoip WHERE as_org LIKE ?", (RELAY_ORG + "%",))
        }
        for e in self._search("idp_signins", upn):
            if e.get("user_upn", "").lower() == upn.lower() and e.get("device_id") and e.get("src_ip") not in geo:
                devices.add(e["device_id"])
        return devices


def alert_context(base: Context, facts: Facts, records: list[tuple[str, dict[str, Any]]]) -> Context:
    """Copy of the base context with the facts the N4 rules need for these events."""
    ctx = copy.copy(base)
    ctx.waf_ok_ips, ctx.ecom_ok_ips = set(), set()
    ctx.known_devices = defaultdict(set)
    for source, e in records:
        ip = e.get("src_ip")
        if source == "waf" and ip and facts.web_success(ip):
            ctx.waf_ok_ips.add(ip)
        if source == "idp_signins" and e.get("user_upn") and e["user_upn"] not in ctx.known_devices:
            ctx.known_devices[e["user_upn"]] = facts.known_devices(e["user_upn"])
    return ctx
