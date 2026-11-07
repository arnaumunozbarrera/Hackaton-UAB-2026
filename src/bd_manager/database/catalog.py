"""Generates db/catalogo_bd.md (data dictionary) and db/schema.sql from the live database."""

import argparse
import pathlib
import re
import sqlite3

LAYER = {
    "Source layer - inventory and business": [
        "usuario",
        "activo",
        "zona_red",
        "tienda",
        "servicio_negocio",
        "activo_servicio",
        "vulnerabilidad",
        "evento_rrhh",
        "cambio",
    ],
    "Source layer - documentation": ["archivo_fuente", "documento"],
    "Source layer - detection and relations": ["regla", "alerta", "alerta_evento", "participacion"],
    "Source layer - events and intelligence": [
        "evento",
        "ocurrencia_indicador",
        "indicador",
        "inteligencia",
        "geoip",
        "sandbox",
    ],
    "System layer - computed results (preserved values)": [
        "resultado_alerta",
        "fact_incident",
        "bridge_alert_incident",
        "fact_attack_step",
    ],
    "System layer - log filtering catalog": [
        "common_log_pattern",
        "log_pattern_match",
    ],
    "Reference layer": ["dim_mitre", "ref_severity_matrix"],
}
DESC = {
    "usuario": "Directory identities (usuarios.csv). user_key = lower(username) is the join key used by the logs.",
    "activo": "CMDB assets (activos.csv) with resolved owner, zone, store and IP indicator.",
    "zona_red": "Network zones and CIDR ranges (zonas_red.csv).",
    "tienda": "Stores and their network (tiendas.csv).",
    "servicio_negocio": "Business services, criticality, impact and owner (servicios_negocio.csv).",
    "activo_servicio": "Asset-service links from both sources (activos.business_service and servicios_negocio.activos).",
    "vulnerabilidad": "Vulnerabilities per asset (vulnerabilidades.csv); cvss_valor = numeric part of severidad_cvss.",
    "evento_rrhh": "HR events: travel, leavers, joiners, role changes (eventos_rrhh.csv).",
    "cambio": "Approved changes and authorised flows (calendario_cambios.csv). Times are local (Europe/Madrid). A match is evidence, not proof.",
    "archivo_fuente": "Every delivered file and project document, byte-identical (zlib) with SHA-256 and row count.",
    "documento": "Text of each document (README, policy, runbooks, schemas, tools, presentation, project docs).",
    "regla": "Detection use cases (catalogo_casos_de_uso.csv); runbook -> documento.codigo.",
    "alerta": "SIEM alerts with the complete original record in datos_json. Holds no system results.",
    "alerta_evento": "Ordered related_events of each alert (15,683 references, no loss).",
    "participacion": "Entities (users, hosts, customers, cloud identities, sessions, processes) observed in an alert OR an event, with role, scope, JSON path and resolution.",
    "evento": "814,471 log events of the 18 sources; datos_json keeps every field. Shortcut columns for fast correlation.",
    "ocurrencia_indicador": "Where each indicator appears: alert, event or sandbox report (exactly one), with role and JSON path.",
    "indicador": "Unique indicators (ip, domain, url, sha256, md5, email). UNIQUE(tipo, valor).",
    "inteligencia": "Internal TIP (ti_feed.jsonl).",
    "geoip": "GeoIP / ASN and anonymisation flags (geoip_asn.csv).",
    "sandbox": "Sandbox reports (sandbox_informes.jsonl); full report in datos_json.",
    "resultado_alerta": "System output per alert (L2): primary entities, dedup hash, verdict, final severity, rationale, authorisation.",
    "fact_incident": "System output: incidents (L2 grouping) and investigation report fields (L3).",
    "bridge_alert_incident": "System output: alert -> incident link with reason and score (L2).",
    "fact_attack_step": "System output: reconstructed attack timeline (L3), evidence origin alert / hidden_log / context.",
    "common_log_pattern": "Reusable catalog of normalized cross-product, benign-expected and noise log patterns. Empty until reviewed patterns are added.",
    "log_pattern_match": "Event-to-pattern decisions used to hide or aggregate non-useful logs without deleting raw evidence.",
    "dim_mitre": "MITRE ATT&CK Enterprise (+ ICS / ATLAS ids used by the dataset): tactic, kill-chain order, data sources, mitigations.",
    "ref_severity_matrix": "Severity matrix of politica_soc.md section 2.",
}
VIEWS = {
    "fact_alert": "Compatibility: alerta + resultado_alerta with the previous column names (INSTEAD OF UPDATE trigger writes to resultado_alerta).",
    "dim_log": "Compatibility: evento with the previous column names.",
    "dim_user": "Compatibility: usuario + latest evento_rrhh.",
    "dim_vulnerability": "Compatibility: activo + service + aggregated vulnerabilities.",
    "dim_context": "Compatibility: indicators with TIP / GeoIP / sandbox data + approved changes.",
    "dim_rule": "Compatibility: regla + runbook sections (Comprobaciones / Decisión) from documento.",
    "bridge_alert_entity": "Compatibility: alert entities (participacion + ocurrencia_indicador), original JSON order.",
    "bridge_alert_event": "Compatibility: alerta_evento.",
    "v_alert_enriched": "Alert with every dimension and the matrix base severity.",
    "v_alert_change_overlap": "Approved changes active at alert time (+ entity_match, window_hours).",
    "v_alert_duplicates": "Groups of identical alerts (rule + entities + day).",
    "v_incident_queue": "Analyst queue ordered by status, severity, SLA.",
    "v_incident_timeline": "L3 timeline with MITRE tactic and kill-chain order.",
    "v_common_log_matches": "Events matched to reusable common/noise patterns.",
    "v_useful_logs": "Raw events excluding enabled patterns marked hide_from_triage; raw data remains in evento.",
    "v_common_log_candidates": "Action/result candidates observed across multiple products for analyst review.",
}


def comments(sql):
    out = {}
    for line in sql.splitlines():
        m = re.match(r"\s*([a-z_0-9]+)\s+[A-Z].*?--\s*(.+)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="tarvia_soc.sqlite")
    ap.add_argument("--out", default=".")
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    out = pathlib.Path(a.out)
    md = [
        "# Tarvia SOC - Data catalog (single main database `tarvia_soc.sqlite`)",
        "",
        "Hybrid SQLite: relations in columns + intact JSON records. 21 source tables (delivered data and documentation), "
        "a system layer with the values computed by L2/L3, a reference layer, and compatibility views so the existing scripts keep working.",
        "",
        "| Layer | Tables |",
        "|---|---|",
    ]
    for layer, ts in LAYER.items():
        md.append(f"| {layer} | {', '.join(ts)} |")
    md += ["", "Generated from the live database by `catalog.py`. PK = primary key, FK = foreign key.", ""]
    for layer, ts in LAYER.items():
        md += [f"## {layer}", ""]
        for t in ts:
            sql = con.execute("SELECT sql FROM sqlite_master WHERE name=?", (t,)).fetchone()[0]
            n = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            fks = {r[3]: f"{r[2]}({r[4]})" for r in con.execute(f"PRAGMA foreign_key_list({t})")}
            cm = comments(sql)
            md += [
                f"### `{t}` - {n:,} rows",
                "",
                DESC.get(t, ""),
                "",
                "| Column | Type | Key | Description |",
                "|---|---|---|---|",
            ]
            for c in con.execute(f"PRAGMA table_info({t})"):
                key = " ".join(x for x in (("PK" if c[5] else ""), (f"FK -> {fks[c[1]]}" if c[1] in fks else "")) if x)
                md.append(f"| {c[1]} | {c[2] or ''} | {key} | {cm.get(c[1], '')} |")
            md.append("")
    md += ["## Views", "", "| View | Purpose |", "|---|---|"] + [f"| `{v}` | {d} |" for v, d in VIEWS.items()] + [""]
    (out / "catalogo_bd.md").write_text("\n".join(md), encoding="utf-8")
    (out / "schema.sql").write_text(
        ";\n\n".join(
            r[0]
            for r in con.execute(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 WHEN 'view' THEN 2 ELSE 3 END, name"
            )
        )
        + ";\n",
        encoding="utf-8",
    )
    print("catalogo_bd.md + schema.sql written")


if __name__ == "__main__":
    main()
