"""Resolve documented alert -> event -> inventory relationships, without severity assumptions.

SQL reads only explicitly cited events, with no time-window or row-limit heuristics.
The CSV contains semantic aliases absent from foreign keys; criticalities always come from inventory.
"""

from __future__ import annotations

import csv
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RELATIONS_PATH = Path(__file__).resolve().parents[1] / "implementation_docs/criticality_relations.csv"


def reviewed_relations() -> list[dict[str, str]]:
    with RELATIONS_PATH.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


PRODUCT_SERVICES: dict[str, tuple[str, ...]] = {}
for _row in reviewed_relations():
    if _row["resource_type"] == "source_product":
        _product = _row["value"]
        PRODUCT_SERVICES[_product] = (*PRODUCT_SERVICES.get(_product, ()), _row["target"])


@dataclass
class AlertScope:
    assets: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    links: set[tuple[str, str, str, str]] = field(default_factory=set)
    unresolved: set[str] = field(default_factory=set)

    def provenance(self) -> list[dict[str, str]]:
        return [dict(zip(("kind", "name", "relation", "reference"), row, strict=True)) for row in sorted(self.links)]


class ScopeIndex:
    def __init__(self, assets, services, asset_services, products, product_services=None):
        self.assets, self.services, self.asset_services = assets, services, asset_services
        self.scopes = {aid: AlertScope() for aid in products}
        self.by_ip: dict[str, set[str]] = defaultdict(set)
        for host, asset in assets.items():
            if asset.get("ip"):
                self.by_ip[asset["ip"]].add(host)
        self.aliases: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
        for row in reviewed_relations():
            self.aliases[row["resource_type"], row["value"]].append(row)
        self.buckets: dict[str, set[str]] = defaultdict(set)
        for name, service in services.items():
            for resource in (service.get("asset_references") or "").split(","):
                if resource.strip().startswith("s3://"):
                    self.buckets[resource.strip()[5:].rstrip("/")].add(name)
        mapping = PRODUCT_SERVICES if product_services is None else product_services
        for aid, product in products.items():
            for name in mapping.get(product, ()):
                evidence = "; ".join(
                    row["source"] for row in self.aliases.get(("source_product", product), ()) if row["target"] == name
                )
                self.add(
                    aid,
                    "service",
                    name,
                    "detection_rules.source_product",
                    f"{product}; {evidence}" if evidence else product,
                )
            self.resource(aid, "source_product_asset", product, f"source_product={product}")

    def add(self, aid: str, kind: str, name: str | None, relation: str, reference: str) -> None:
        if not name:
            return
        scope = self.scopes[aid]
        if name not in (self.assets if kind == "asset" else self.services):
            scope.unresolved.add(f"{relation}: {name} ({reference})")
            return
        (scope.assets if kind == "asset" else scope.services).add(name)
        scope.links.add((kind, name, relation, reference))

    def resource(self, aid: str, kind: str, value: str | None, reference: str) -> None:
        if not value:
            return
        # target_resource can be a path inside a named application, not an inventory hostname.
        if kind == "idp_resource":
            value = value.split("/", 1)[0]
        for row in self.aliases.get((kind, value), ()):
            self.add(aid, row["target_type"], row["target"], f"{kind}={value}", f"{reference}; {row['source']}")
        if kind == "cloud_bucket":
            for name in self.buckets.get(value, ()):
                self.add(aid, "service", name, "business_services.asset_references", f"{reference}; s3://{value}")

    def log(
        self, aid: str, source: str, event_id: str, assets: dict[str, str | None], resources: dict[str, str | None]
    ):
        self.resource(aid, "log_source", source, event_id)
        for role, host in assets.items():
            self.add(aid, "asset", host, role, event_id)
        for kind, value in resources.items():
            if kind in ("firewall_src_ip", "firewall_dst_ip"):
                for host in self.by_ip.get(value, ()):
                    self.add(aid, "asset", host, kind, event_id)
            else:
                self.resource(aid, kind, value, event_id)

    def finish(self) -> dict[str, AlertScope]:
        for aid, scope in self.scopes.items():
            for host in sorted(scope.assets):
                primary = self.assets[host].get("business_service")
                if primary:
                    self.add(aid, "service", primary, "assets.business_service", host)
                for name in sorted(self.asset_services.get(host, ())):
                    self.add(aid, "service", name, "asset_services", host)
        return self.scopes


# These projections use only schema-owned identifiers. Values never become SQL text.
RESOURCE_COLUMNS = {
    "idp_signins": {"idp_app": "app"},
    "idp_audit": {"idp_resource": "target_resource"},
    "dlp": {"dlp_channel": "channel"},
    "cloudtrail": {
        "cloud_identity": "identity_name",
        "cloud_bucket": "json_extract(request_parameters_json, '$.bucketName')",
    },
    "sql_audit": {"sql_database": '"database"'},
    "firewall": {"firewall_src_ip": "src_ip", "firewall_dst_ip": "dst_ip"},
}


def load_db_scopes(conn: sqlite3.Connection, product_services=None) -> dict[str, AlertScope]:
    from .database.logs import SPECS

    assets = {
        h: {"business_service": bs, "ip": ip}
        for h, bs, ip in conn.execute("SELECT hostname,business_service,ip FROM assets")
    }
    asset_names = dict(conn.execute("SELECT asset_id,hostname FROM assets"))
    services = {
        n: {"asset_references": refs} for n, refs in conn.execute("SELECT name,asset_references FROM business_services")
    }
    links: dict[str, set[str]] = defaultdict(set)
    for host, name in conn.execute(
        "SELECT a.hostname,s.name FROM asset_services x JOIN assets a USING(asset_id) JOIN business_services s USING(service_id)"
    ):
        links[host].add(name)
    products = dict(
        conn.execute("SELECT a.alert_id,r.source_product FROM alerts a JOIN detection_rules r USING(rule_id)")
    )
    index = ScopeIndex(assets, services, links, products, product_services)
    for aid, host in conn.execute("SELECT x.alert_id,a.hostname FROM alert_assets x JOIN assets a USING(asset_id)"):
        index.add(aid, "asset", host, "alert_assets", aid)
    for aid, identity, bucket in conn.execute("SELECT alert_id,identity,bucket FROM alert_cloud"):
        index.resource(aid, "cloud_identity", identity, "alert_cloud.identity")
        index.resource(aid, "cloud_bucket", bucket, "alert_cloud.bucket")
    for source, spec in SPECS.items():
        asset_columns = list(spec.assets.values())
        resources = RESOURCE_COLUMNS.get(source, {})
        columns = [f"t.{column}" for column in asset_columns] + [
            f"t.{column}" if "(" not in column else column for column in resources.values()
        ]
        select = ", " + ", ".join(columns) if columns else ""
        # SPECS and RESOURCE_COLUMNS are internal constants, never external identifiers.
        query = f"SELECT e.alert_id,t.event_id{select} FROM alert_events e JOIN {spec.table} t ON t.event_id=e.event_id"  # noqa: S608
        for aid, eid, *values in conn.execute(query):
            hosts = {}
            for role, asset_id in zip(asset_columns, values, strict=False):
                if asset_id:
                    hosts[spec.table + "." + role] = asset_id
            # FK values are resolved in one inventory lookup, never via user ownership or assigned device.
            if hosts:
                hosts = {role: asset_names.get(asset_id) for role, asset_id in hosts.items()}
            index.log(aid, source, eid, hosts, dict(zip(resources, values[len(asset_columns) :], strict=True)))
    return index.finish()


def load_dataset_scopes(data: Path, assets, services, links, alerts, product_services=None) -> dict[str, AlertScope]:
    from .database.logs import SPECS
    from .log_noise_discard.loaders import iter_source
    from .log_noise_discard.templates import SOURCES

    inventory_services = {name: {"asset_references": row.get("activos")} for name, row in services.items()}
    index = ScopeIndex(
        assets, inventory_services, links, {aid: a["source_product"] for aid, a in alerts.items()}, product_services
    )
    event_alerts: dict[str, set[str]] = defaultdict(set)
    for aid, alert in alerts.items():
        for host in (alert.get("entities") or {}).get("hosts", []):
            name = host.get("hostname") if isinstance(host, dict) else host
            index.add(aid, "asset", name, "alert_assets", aid)
        cloud = (alert.get("entities") or {}).get("cloud") or {}
        index.resource(aid, "cloud_identity", cloud.get("identity"), "alert_cloud.identity")
        index.resource(aid, "cloud_bucket", cloud.get("bucket"), "alert_cloud.bucket")
        for eid in alert.get("related_events") or []:
            event_alerts[eid].add(aid)
    seen = set()
    for source, spec in SPECS.items():
        source_spec = SOURCES[source]
        if not (data / "04_logs" / source_spec.file).exists():
            continue
        for event, _ in iter_source(data, source_spec):
            eid = event["event_id"]
            if eid not in event_alerts:
                continue
            seen.add(eid)
            hosts = {spec.table + "." + role: event.get(key) for key, role in spec.assets.items()}
            resources: dict[str, Any] = {}
            if source == "idp_signins":
                resources["idp_app"] = event.get("app")
            elif source == "idp_audit":
                resources["idp_resource"] = event.get("target")
            elif source == "dlp":
                resources["dlp_channel"] = event.get("channel")
            elif source == "cloudtrail":
                resources["cloud_identity"] = (event.get("userIdentity") or {}).get("userName")
                resources["cloud_bucket"] = (event.get("requestParameters") or {}).get("bucketName")
            elif source == "sql_audit":
                resources["sql_database"] = event.get("database")
            elif source == "firewall":
                resources.update(firewall_src_ip=event.get("src_ip"), firewall_dst_ip=event.get("dst_ip"))
            for aid in event_alerts[eid]:
                index.log(aid, source, eid, hosts, resources)
    for eid in event_alerts.keys() - seen:
        for aid in event_alerts[eid]:
            index.scopes[aid].unresolved.add(f"alert_events: evento no disponible {eid}")
    return index.finish()
