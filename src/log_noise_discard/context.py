"""Authoritative context used by stage N4 (activity already explained).

Why: a log whose activity is fully described by an approved change, a documented company rule, a TIP/GeoIP
label, a sandbox verdict or an HR record adds no information to triage. This module loads those sources once
(read-only) and collects the few dataset-wide facts that N4 conditions need (e.g. "the scanner never got a 2xx").
"""

from __future__ import annotations

import csv
import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .templates import normalise_identity

MADRID = ZoneInfo("Europe/Madrid")  # the change calendar is in local time
RELAY_ORG = "Microsoft (salida de Private Relay"


def parse_ts(value: str) -> datetime:
    """ISO-8601 UTC timestamp from the logs ('Z' suffix accepted)."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _local_to_utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d %H:%M").replace(tzinfo=MADRID).astimezone(timezone.utc)


@dataclass(frozen=True)
class Change:
    """Approved change or authorised flow with its window converted to UTC."""

    id: str
    title: str
    start: datetime
    end: datetime
    detail: str
    scope: str

    def covers(self, ts: datetime) -> bool:
        return self.start <= ts <= self.end


@dataclass(frozen=True)
class Trip:
    user: str
    start: date
    end: date


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _trips(rows: list[dict[str, str]]) -> list[Trip]:
    trips = []
    for row in rows:
        if row["tipo"] != "viaje":
            continue
        m = re.search(r"del (\d{2})/(\d{2}) al (\d{2})/(\d{2})", row["detalle"])
        start = date(2026, int(m[2]), int(m[1])) if m else date.fromisoformat(row["fecha_efectiva"])
        end = date(2026, int(m[4]), int(m[3])) if m else start + timedelta(days=7)
        trips.append(Trip(normalise_identity(row["usuario"]), start, end))
    return trips


@dataclass
class Context:
    """Read-only reference data plus dataset-wide facts gathered while streaming the logs."""

    geo: dict[str, dict[str, str]]
    ti: dict[str, dict[str, Any]]
    sandbox: dict[str, dict[str, Any]]
    assets: dict[str, dict[str, str]]
    zones: list[tuple[Any, str]]
    changes: list[Change]
    trips: list[Trip]
    leavers: set[str]
    waf_ok_ips: set[str] = field(default_factory=set)
    ecom_ok_ips: set[str] = field(default_factory=set)
    known_devices: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    @property
    def bad_indicators(self) -> set[str]:
        return {k for k, v in self.ti.items() if v["reputation"] in ("malicious", "suspicious")}

    @property
    def benign_domains(self) -> set[str]:
        """TIP benign domains, excluding dual-use services (policy: not allow-listed globally)."""
        return {k for k, v in self.ti.items() if v["reputation"] == "benign" and "depende del uso" not in v["note"]}

    def org(self, ip: str | None) -> str:
        return self.geo.get(ip or "", {}).get("as_org", "")

    def asset_ip(self, hostname: str) -> str:
        return self.assets.get(hostname, {}).get("ip", "")

    def observe(self, source: str, event: dict[str, Any]) -> None:
        """Collect facts needed by N4 from every event (cited or not)."""
        if source == "waf" and event["action"] == "allowed" and str(event["status"])[:1] in "23":
            self.waf_ok_ips.add(event["src_ip"])
        elif source == "ecom_auth" and event["result"] == "success":
            self.ecom_ok_ips.add(event["src_ip"])
        elif source == "idp_signins" and event["device_id"] and not self.org(event["src_ip"]).startswith(RELAY_ORG):
            self.known_devices[event["user_upn"]].add(event["device_id"])


def load_context(data_dir: Path) -> Context:
    """Load inventory, change calendar, HR events, TIP, GeoIP and sandbox reports."""
    inv, intel = data_dir / "02_inventario", data_dir / "05_inteligencia"
    hr = _read_csv(inv / "eventos_rrhh.csv")
    changes = [
        Change(r["id"], r["titulo"], _local_to_utc(r["inicio"]), _local_to_utc(r["fin"]), r["detalle"], r["alcance"])
        for r in _read_csv(inv / "calendario_cambios.csv")
    ]
    return Context(
        geo={r["ip"]: r for r in _read_csv(intel / "geoip_asn.csv")},
        ti={d["value"].lower(): d for d in _read_jsonl(intel / "ti_feed.jsonl")},
        sandbox={d["sha256"]: d for d in _read_jsonl(intel / "sandbox_informes.jsonl")},
        assets={r["hostname"]: r for r in _read_csv(inv / "activos.csv")},
        zones=[(ipaddress.ip_network(r["cidr"]), r["zona"]) for r in _read_csv(inv / "zonas_red.csv")],
        changes=changes,
        trips=_trips(hr),
        leavers={normalise_identity(r["usuario"]) for r in hr if r["tipo"].startswith("baja")},
    )
