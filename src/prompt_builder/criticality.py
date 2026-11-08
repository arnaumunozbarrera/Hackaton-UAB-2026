"""Shared inputs to the severity matrix; no post-matrix adjustments live here."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .policy import most_critical


@dataclass(frozen=True)
class CriticalityAssessment:
    level: str
    origin: str
    candidates: tuple[tuple[str, str | None], ...]


def assess_criticality(
    assets: list[tuple[str, str | None]],
    services: list[tuple[str, str | None]],
) -> CriticalityAssessment:
    """Compare recorded asset and service criticalities, retaining the existing Media fallback."""
    candidates = [(f"activo {name}", level) for name, level in assets]
    candidates += [(f"servicio {name}", level) for name, level in services]
    level = most_critical([value for _, value in candidates])
    origin = (
        "; ".join(name for name, value in candidates if value == level)
        if level
        else "sin criticidad conocida: Media por defecto"
    )
    return CriticalityAssessment(level or "Media", origin, tuple(candidates))


def load_asset_services(conn: sqlite3.Connection) -> dict[str, set[str]]:
    """All reviewed N:M service relations, keyed by hostname, without a row limit."""
    result: dict[str, set[str]] = {}
    for hostname, service in conn.execute(
        "SELECT a.hostname, s.name FROM asset_services x "
        "JOIN assets a ON a.asset_id = x.asset_id "
        "JOIN business_services s ON s.service_id = x.service_id"
    ):
        result.setdefault(hostname, set()).add(service)
    return result


def affected_service_names(
    hosts: list[tuple[str, str | None]],
    links: dict[str, set[str]],
    product_services: tuple[str, ...] = (),
) -> set[str]:
    names = set(product_services)
    for hostname, primary in hosts:
        if primary:
            names.add(primary)
        names.update(links.get(hostname, ()))
    return names
