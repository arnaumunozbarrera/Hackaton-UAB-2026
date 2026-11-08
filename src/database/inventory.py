"""Load the original context inventories and the three approved relation CSVs."""

import ipaddress
import re

from .core import Directory, Sources, Writer, fields, timestamp

USER_FIELDS = {
    "user_id",
    "username",
    "upn",
    "display_name",
    "department",
    "title",
    "location",
    "manager_upn",
    "account_type",
    "privileged",
    "vip",
    "mfa_method",
    "status",
    "created",
    "workstation",
    "notes",
}
ASSET_FIELDS = {
    "asset_id",
    "hostname",
    "ip",
    "type",
    "os",
    "criticality",
    "zone",
    "location",
    "business_service",
    "owner_upn",
    "internet_facing",
    "edr_installed",
    "description",
}


def mapped(row: dict, mapping: dict[str, str], location: str) -> dict:
    fields(row, set(mapping), location)
    return {destination: row.get(source) for source, destination in mapping.items()}


def load_users(writer: Writer, rows: list[dict], directory: Directory) -> None:
    for source in rows:
        fields(source, USER_FIELDS, "usuarios.csv")
        row = {key: value for key, value in source.items() if key not in {"manager_upn", "workstation"}}
        row["manager_user_id"] = directory.require_user(source["manager_upn"])
        row["workstation_asset_id"] = directory.asset(source["workstation"])
        writer.add("users", row)


def load_assets(writer: Writer, rows: list[dict], directory: Directory, stores: list[dict]) -> None:
    networks = [(store["tienda"], ipaddress.ip_network(store["red"])) for store in stores]
    for source in rows:
        fields(source, ASSET_FIELDS, "activos.csv")
        row = {key: value for key, value in source.items() if key not in {"zone", "owner_upn"}}
        matches = [store for store, network in networks if ipaddress.ip_address(source["ip"]) in network]
        if len(matches) > 1:
            raise ValueError("Overlapping store networks make store_id ambiguous")
        row.update(
            zone_id=source["zone"],
            owner_user_id=directory.require_user(source["owner_upn"]),
            store_id=matches[0] if matches else None,
        )
        writer.add("assets", row)


def load_runbooks(writer: Writer, sources: Sources) -> None:
    for path in sorted((sources.data / "01_contexto/runbooks").glob("RB-*.md")):
        text = sources.document(path.relative_to(sources.data).as_posix())
        heading = re.search(r"^#\s+(RB-\d+)\s+(.+)$", text, re.M)
        checks = re.search(r"^## Comprobaciones\s*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
        decision = re.search(r"^## Decisión\s*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
        if not all([heading, checks, decision]):
            raise ValueError(f"Unrecognized runbook structure: {path.name}")
        writer.add(
            "runbooks",
            {
                "runbook_id": heading[1],
                "title": heading[2].strip(),
                "checks_text": checks[1].strip(),
                "decision_guidance_text": decision[1].strip(),
            },
        )


def load_rules(writer: Writer, sources: Sources) -> dict[str, dict]:
    mapping = {
        "rule_id": "rule_id",
        "nombre": "name",
        "fuente": "source_product",
        "severidad_base": "base_severity",
        "tactica": "tactic",
        "tecnica_id": "technique_id",
        "tecnica": "technique_name",
        "runbook": "runbook_id",
        "logica": "detection_logic",
    }
    rules = {}
    for source in sources.records("01_contexto/catalogo_casos_de_uso.csv"):
        row = mapped(source, mapping, "catalogo_casos_de_uso.csv")
        writer.add("detection_rules", row)
        rules[row["rule_id"]] = row
    return rules


def load_context_events(writer: Writer, sources: Sources, directory: Directory) -> None:
    mapping = {
        "fecha": "recorded_date",
        "tipo": "event_type",
        "usuario": "user_id",
        "detalle": "details",
        "fecha_efectiva": "effective_date",
    }
    for position, source in enumerate(sources.records("02_inventario/eventos_rrhh.csv"), 1):
        row = mapped(source, mapping, "eventos_rrhh.csv")
        row.update(hr_event_id=position, user_id=directory.require_user(source["usuario"]))
        writer.add("hr_events", row)
    mapping = {
        "hostname": "asset_id",
        "id": "reference",
        "producto": "product",
        "severidad_cvss": "cvss",
        "estado": "status",
        "detectada": "detected_date",
        "notas": "notes",
    }
    for position, source in enumerate(sources.records("02_inventario/vulnerabilidades.csv"), 1):
        row = mapped(source, mapping, "vulnerabilidades.csv")
        row.update(vulnerability_id=position, asset_id=directory.asset(source["hostname"]))
        writer.add("vulnerabilities", row)


def load_changes(writer: Writer, sources: Sources) -> None:
    mapping = {
        "id": "change_id",
        "titulo": "title",
        "inicio": "start_at",
        "fin": "end_at",
        "solicitante": "requester",
        "detalle": "details",
        "alcance": "scope",
    }
    for source in sources.records("02_inventario/calendario_cambios.csv"):
        row = mapped(source, mapping, "calendario_cambios.csv")
        row["start_at"] = timestamp(source["inicio"], local=True)
        row["end_at"] = timestamp(source["fin"], local=True)
        writer.add("changes", row)


def load_inventory(writer: Writer, sources: Sources) -> tuple[Directory, dict[str, dict]]:
    users = list(sources.records("02_inventario/usuarios.csv"))
    assets = list(sources.records("02_inventario/activos.csv"))
    stores = list(sources.records("02_inventario/tiendas.csv"))
    directory = Directory(users, assets)
    for row in stores:
        writer.add(
            "stores",
            mapped(row, {"tienda": "store_id", "nombre": "name", "ciudad": "city", "red": "cidr"}, "tiendas.csv"),
        )
    for row in sources.records("02_inventario/zonas_red.csv"):
        directory.zones.add(row["zona"])
        writer.add(
            "network_zones",
            mapped(
                row,
                {"zona": "zone_id", "cidr": "cidr", "ubicacion": "location", "descripcion": "description"},
                "zonas_red.csv",
            ),
        )
    for position, row in enumerate(sources.records("02_inventario/servicios_negocio.csv"), 1):
        service = mapped(
            row,
            {
                "servicio": "name",
                "criticidad": "criticality",
                "impacto": "impact",
                "activos": "asset_references",
                "responsable": "owner_role",
            },
            "servicios_negocio.csv",
        )
        writer.add("business_services", {"service_id": position, **service})
    load_users(writer, users, directory)
    load_assets(writer, assets, directory, stores)
    load_context_events(writer, sources, directory)
    load_changes(writer, sources)
    load_runbooks(writer, sources)
    rules = load_rules(writer, sources)
    for table in ["asset_services", "change_assets", "change_users"]:
        for row in sources.records(table + ".csv", derived=True):
            writer.add(table, row)
    return directory, rules
