"""Known open vulnerabilities per host, added to the canonical alert text.

Why: whether the alerted host carries an open, known vulnerability (CVE or vendor advisory) is internal inventory
context that changes how an N1 analyst reads the alert, and it is trusted data (not attacker-controlled). Only open
vulnerabilities are used; the free-text notes are left out so they do not dominate the vector.
"""

from __future__ import annotations

import csv
import sqlite3
from collections import defaultdict
from pathlib import Path

VulnIndex = dict[str, list[str]]


def _fmt(reference: object, product: object, cvss: object, criticality: object, internet_facing: object) -> str:
    exposure = "internet" if str(internet_facing).strip().lower() in ("1", "true", "yes") else "internal"
    return f"{reference} {product} cvss={cvss} criticality={criticality or '?'} exposure={exposure}"


def _finish(index: dict[str, list[str]]) -> VulnIndex:
    return {host: sorted(set(rows)) for host, rows in index.items()}


def from_db(conn: sqlite3.Connection) -> VulnIndex:
    """hostname (lower) -> open vulnerabilities, from the `vulnerabilities` and `assets` tables."""
    index: dict[str, list[str]] = defaultdict(list)
    try:
        rows = conn.execute(
            "SELECT a.hostname, v.reference, v.product, v.cvss, a.criticality, a.internet_facing "
            "FROM vulnerabilities v JOIN assets a ON a.asset_id = v.asset_id WHERE v.status = 'abierta'"
        ).fetchall()
    except sqlite3.OperationalError:  # database without inventory tables
        return {}
    for host, *rest in rows:
        if host:
            index[host.lower()].append(_fmt(*rest))
    return _finish(index)


def from_csv(data_dir: str | Path) -> VulnIndex:
    """Same index from docs/02_inventario/vulnerabilidades.csv and activos.csv (CLI, no database)."""
    inventory = Path(data_dir) / "02_inventario"
    vulns_path = inventory / "vulnerabilidades.csv"
    if not vulns_path.exists():
        return {}
    assets: dict[str, dict[str, str]] = {}
    assets_path = inventory / "activos.csv"
    if assets_path.exists():
        with assets_path.open(encoding="utf-8", newline="") as fh:
            assets = {row["hostname"].lower(): row for row in csv.DictReader(fh)}
    index: dict[str, list[str]] = defaultdict(list)
    with vulns_path.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            if row.get("estado") != "abierta":
                continue
            host = row["hostname"].lower()
            asset = assets.get(host, {})
            index[host].append(
                _fmt(
                    row["id"],
                    row["producto"],
                    row["severidad_cvss"],
                    asset.get("criticality"),
                    asset.get("internet_facing"),
                )
            )
    return _finish(index)
