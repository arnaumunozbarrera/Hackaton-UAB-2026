"""Regression tests for complete, consistent inputs to the severity matrix."""

import csv
import sqlite3
from pathlib import Path

import pytest

from src.criticality_scope import load_db_scopes
from src.database.enrich import PIPELINE_SQL, VIEWS, _create_alert_tables
from src.database.schema import SCHEMA_PATH
from src.llm_triage.backend import DatasetToolBackend
from src.prompt_builder import DatasetContextSource, DbContextSource, PromptBuilder
from src.prompt_builder.criticality import assess_criticality

DOCS = Path("docs")


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.executescript(PIPELINE_SQL.read_text(encoding="utf-8"))
    conn.execute("CREATE VIEW dim_user AS " + VIEWS["dim_user"])
    conn.execute("CREATE VIEW bridge_alert_entity AS " + VIEWS["bridge_alert_entity"])
    conn.execute("CREATE TABLE dim_context(context_key TEXT, reputation TEXT, sandbox_verdict TEXT)")
    conn.execute("INSERT INTO detection_rules(rule_id, name, source_product) VALUES ('R1', 'Test', 'EDR')")
    conn.execute(
        "INSERT INTO alerts(alert_id, created_at, rule_id, severity) VALUES ('A1', '2026-10-10T10:00:00Z', 'R1', 'medium')"
    )
    conn.executemany(
        "INSERT INTO assets(asset_id, hostname, ip, criticality, business_service) VALUES (?, ?, ?, ?, ?)",
        [("H1", "WS-1", "10.0.0.1", "Baja", "Primary"), ("H2", "WS-2", "10.0.0.2", "Alta", None)],
    )
    conn.executemany(
        "INSERT INTO business_services(service_id, name, criticality) VALUES (?, ?, ?)",
        [(1, "Primary", "Media"), (2, "Secondary", "Crítica"), (3, "Tienda online y app", "Crítica")],
    )
    conn.execute("INSERT INTO alert_assets VALUES ('A1', 'H1')")
    conn.execute("INSERT INTO asset_services VALUES ('H1', 2)")
    conn.executemany(
        "INSERT INTO users(user_id, username, upn, vip, privileged) VALUES (?, ?, ?, ?, ?)",
        [
            ("U1", "ordinary", "ordinary@tarvia.example", 0, 0),
            ("U2", "vip", "vip@tarvia.example", 1, 0),
            ("U3", "admin", "admin@tarvia.example", 0, 1),
        ],
    )
    yield conn
    conn.close()


def both_paths(conn):
    _create_alert_tables(conn, DOCS, False)
    source = DbContextSource(conn)
    builder = PromptBuilder(source)
    package = builder.build("A1")
    cached = conn.execute(
        "SELECT asset_criticality, matrix_base_severity FROM alert_enriched WHERE alert_id='A1'"
    ).fetchone()
    dataset_view = DatasetToolBackend(source, builder)._alert_enriched("A1")[0]
    assert cached == (package.metadata["criticality"], package.metadata["base_severity"])
    assert cached == (dataset_view["asset_criticality"], dataset_view["matrix_base_severity"])
    return source.get("A1"), package, cached


def test_all_services_and_assets_are_considered(db):
    db.execute("INSERT INTO alert_assets VALUES ('A1', 'H2')")
    ctx, package, result = both_paths(db)
    assert {s.name for s in ctx.services} == {"Primary", "Secondary"}
    assert {h.hostname for h in ctx.hosts} == {"WS-1", "WS-2"}
    assert result == ("Crítica", "high")
    assert "servicio Secondary" in package.metadata["criticality_origin"]


def test_service_join_has_no_row_limit(db):
    db.execute("DELETE FROM asset_services")
    for i in range(4, 65):
        db.execute(
            "INSERT INTO business_services(service_id, name, criticality) VALUES (?, ?, ?)",
            (i, f"Service-{i:02d}", "Crítica" if i == 64 else "Baja"),
        )
        db.execute("INSERT INTO asset_services VALUES ('H1', ?)", (i,))
    ctx, _, result = both_paths(db)
    assert len(ctx.services) == 62
    assert result == ("Crítica", "high")


@pytest.mark.parametrize("user", ["U2", "U3"])
def test_identity_flags_do_not_supply_asset_or_service_criticality(db, user):
    db.execute("DELETE FROM asset_services")
    db.executemany("INSERT INTO alert_users VALUES ('A1', ?)", [("U1",), (user,)])
    _, _, result = both_paths(db)
    assert result == ("Media", "medium")
    db.execute("UPDATE assets SET business_service=NULL WHERE asset_id='H1'")
    assert both_paths(db)[2] == ("Baja", "low")
    db.execute("DELETE FROM alert_assets")
    assert both_paths(db)[2] == ("Media", "medium")  # existing unknown-criticality fallback


def test_product_mapping_without_host(db):
    db.execute("DELETE FROM alert_assets")
    db.execute("UPDATE detection_rules SET source_product='WAF'")
    ctx, _, result = both_paths(db)
    assert [s.name for s in ctx.services] == ["Tienda online y app"]
    assert result == ("Crítica", "high")


def test_indicator_ip_does_not_claim_an_asset_is_affected(db):
    db.execute("DELETE FROM alert_assets")
    db.execute("INSERT INTO alert_indicators VALUES ('A1', 'ip', '10.0.0.2')")
    # An assigned workstation is context, not proof that it is affected either.
    db.execute("UPDATE users SET workstation_asset_id='H2' WHERE user_id='U1'")
    db.execute("INSERT INTO alert_users VALUES ('A1', 'U1')")
    ctx, _, result = both_paths(db)
    assert not ctx.hosts and not ctx.services
    assert result == ("Media", "medium")


def test_refresh_recomputes_inventory_identities_relations_and_matrix(db, tmp_path):
    assert both_paths(db)[2] == ("Crítica", "high")
    db.execute("UPDATE business_services SET criticality='Baja' WHERE service_id=2")
    assert both_paths(db)[2] == ("Media", "medium")
    db.execute("INSERT INTO alert_users VALUES ('A1', 'U1')")
    db.execute("UPDATE users SET privileged=1 WHERE user_id='U1'")
    assert both_paths(db)[2] == ("Media", "medium")
    db.execute("INSERT INTO asset_services VALUES ('H1', 3)")
    assert both_paths(db)[2] == ("Crítica", "high")
    db.execute("DELETE FROM asset_services")
    db.execute("UPDATE users SET privileged=0")
    db.execute("UPDATE assets SET criticality='Crítica' WHERE asset_id='H1'")
    assert both_paths(db)[2] == ("Crítica", "high")
    policy_dir = tmp_path / "01_contexto"
    policy_dir.mkdir()
    policy = (DOCS / "01_contexto/politica_soc.md").read_text(encoding="utf-8")
    (policy_dir / "politica_soc.md").write_text(
        policy.replace("| medium | low | medium | medium | high |", "| medium | low | medium | medium | critical |"),
        encoding="utf-8",
    )
    assert _create_alert_tables(db, tmp_path, False) == 0  # updated, not newly inserted
    assert db.execute("SELECT matrix_base_severity FROM alert_enriched").fetchone() == ("critical",)


def test_unknown_levels_do_not_mask_known_candidates():
    result = assess_criticality([("unknown", None), ("misspelt", "alta")], [("S", "Alta")])
    assert result.level == "Alta" and result.origin == "servicio S"
    assert result.candidates[0] == ("activo unknown", None)
    assert assess_criticality([], []).level == "Media"


def test_dataset_reads_reviewed_service_relations(tmp_path):
    data = tmp_path / "docs"
    inventory = data / "02_inventario"
    inventory.mkdir(parents=True)
    (data / "01_contexto").mkdir()
    (data / "03_alertas").mkdir()
    relations = tmp_path / "implementation_docs"
    relations.mkdir()

    def write_csv(path, header, rows):
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(header)
            writer.writerows(rows)

    write_csv(
        inventory / "activos.csv",
        ["asset_id", "hostname", "criticality", "business_service", "zone", "type"],
        [["H1", "WS-1", "Baja", "Primary", "IT", "PC"]],
    )
    write_csv(
        inventory / "servicios_negocio.csv",
        ["servicio", "criticidad", "activos", "responsable"],
        [["Primary", "Media", "WS-1", "IT"], ["Secondary", "Crítica", "WS-1", "IT"]],
    )
    write_csv(inventory / "usuarios.csv", ["username"], [])
    write_csv(inventory / "eventos_rrhh.csv", ["usuario", "tipo"], [])
    write_csv(data / "01_contexto/catalogo_casos_de_uso.csv", ["rule_id"], [])
    write_csv(relations / "asset_services.csv", ["asset_id", "service_id"], [["H1", "2"]])
    (data / "03_alertas/alertas.jsonl").write_text("", encoding="utf-8")
    source = DatasetContextSource(data)
    hosts, unknown = source._hosts(["WS-1"])
    assert not unknown
    assert {s.name: s.criticality for s in source._services("EDR", hosts)} == {
        "Primary": "Media",
        "Secondary": "Crítica",
    }


@pytest.mark.parametrize(
    "source,table,column",
    [
        ("ad_events", "ad_events_logs", "dc_asset_id"),
        ("ad_events", "ad_events_logs", "source_asset_id"),
        ("edr_events", "edr_logs", "asset_id"),
        ("proxy", "proxy_logs", "asset_id"),
        ("dns", "dns_logs", "asset_id"),
        ("dlp", "dlp_logs", "asset_id"),
        ("sql_audit", "sql_audit_logs", "client_asset_id"),
        ("cicd_builds", "cicd_builds_logs", "runner_asset_id"),
    ],
)
def test_cited_event_foreign_keys_reach_inventory(db, source, table, column):
    db.execute("DELETE FROM alert_assets")
    db.execute("INSERT INTO assets(asset_id,hostname,criticality) VALUES ('H3','UNRELATED','Crítica')")
    db.executemany(
        "INSERT INTO logs(event_id,timestamp,source) VALUES (?, '2026-10-10T10:00:00Z', ?)",
        [("E1", source), ("E2", source)],
    )
    # Identifiers in this parametrization are internal schema constants.
    db.executemany(f"INSERT INTO {table}(event_id,{column}) VALUES (?, ?)", [("E1", "H2"), ("E2", "H3")])  # noqa: S608
    db.execute("INSERT INTO alert_events VALUES ('A1',0,'E1')")
    ctx, package, result = both_paths(db)
    assert {h.hostname for h in ctx.hosts} == {"WS-2"}
    assert result == ("Alta", "medium")
    assert any(
        r["relation"] == f"{table}.{column}" and r["reference"] == "E1"
        for r in package.metadata["criticality_inputs"]["relations"]
    )


@pytest.mark.parametrize(
    "product,name,criticality",
    [
        ("EMAIL_GW", "Correo y colaboración (SaaS)", "Alta"),
        ("IDP", "Identidad y directorio activo", "Crítica"),
    ],
)
def test_documented_saas_service_without_host(db, product, name, criticality):
    db.execute("DELETE FROM alert_assets")
    db.execute("UPDATE detection_rules SET source_product=?", (product,))
    db.execute("INSERT INTO business_services(service_id,name,criticality) VALUES (20,?,?)", (name, criticality))
    ctx, _, result = both_paths(db)
    assert not ctx.hosts
    assert {s.name for s in ctx.services} == {name}
    assert result[0] == criticality


def test_vpn_resolves_documented_gateway_without_using_assigned_ip(db):
    db.execute("DELETE FROM alert_assets")
    db.execute("UPDATE detection_rules SET source_product='VPN'")
    db.execute("INSERT INTO assets(asset_id,hostname,criticality) VALUES ('GW','VPN-GW01','Crítica')")
    db.execute("INSERT INTO logs VALUES ('V1','2026-10-10T10:00:00Z','vpn')")
    db.execute("INSERT INTO vpn_logs(event_id,user_id,assigned_ip) VALUES ('V1','U1','10.0.0.2')")
    db.execute("INSERT INTO alert_events VALUES ('A1',0,'V1')")
    ctx, _, result = both_paths(db)
    assert {h.hostname for h in ctx.hosts} == {"VPN-GW01"}
    assert result == ("Crítica", "high")


def test_cloud_bucket_joins_catalog_resource_exactly(db):
    db.execute("DELETE FROM alert_assets")
    db.execute("UPDATE detection_rules SET source_product='CLOUD'")
    db.execute(
        "INSERT INTO business_services(service_id,name,criticality,asset_references) VALUES (20,'Backups','Alta','BACKUP01, s3://private-backups')"
    )
    db.execute("INSERT INTO logs VALUES ('C1','2026-10-10T10:00:00Z','cloudtrail')")
    db.execute(
        "INSERT INTO cloudtrail_logs(event_id,request_parameters_json) VALUES ('C1','{\"bucketName\":\"private-backups\"}')"
    )
    db.execute("INSERT INTO alert_events VALUES ('A1',0,'C1')")
    assert both_paths(db)[2] == ("Alta", "medium")
    db.execute('UPDATE cloudtrail_logs SET request_parameters_json=\'{"bucketName":"private-backups.evil"}\'')
    scope = load_db_scopes(db)["A1"]
    assert not scope.assets and not scope.services


def test_cloud_identity_uses_explicit_credential_dependency_not_directory_name(db):
    db.execute("DELETE FROM alert_assets")
    db.execute("INSERT INTO assets(asset_id,hostname,criticality) VALUES ('CI','CI-RUNNER01','Alta')")
    db.execute("INSERT INTO alert_cloud(alert_id,identity) VALUES ('A1','svc_ecom_deploy')")
    assert both_paths(db)[2] == ("Alta", "medium")
    db.execute("UPDATE alert_cloud SET identity='admin'")  # same spelling as a directory account is not a relation
    scope = load_db_scopes(db)["A1"]
    assert not scope.assets and not scope.services


def test_firewall_endpoints_are_resolved_but_indicators_are_not(db):
    db.execute("DELETE FROM alert_assets")
    db.execute("INSERT INTO logs VALUES ('F1','2026-10-10T10:00:00Z','firewall')")
    db.execute("INSERT INTO firewall_logs(event_id,src_ip,dst_ip) VALUES ('F1','203.0.113.1','10.0.0.2')")
    db.execute("INSERT INTO alert_events VALUES ('A1',0,'F1')")
    db.execute("INSERT INTO alert_indicators VALUES ('A1','ip','10.0.0.1')")
    ctx, _, result = both_paths(db)
    assert {h.hostname for h in ctx.hosts} == {"WS-2"}
    assert result == ("Alta", "medium")


def test_missing_alias_target_is_reported_without_inventing_criticality(db):
    db.execute("DELETE FROM alert_assets")
    db.execute("UPDATE detection_rules SET source_product='VPN'")
    scope = load_db_scopes(db)["A1"]
    assert not scope.assets and any("VPN-GW01" in reason for reason in scope.unresolved)


def test_arbitrary_evidence_is_not_an_inventory_relation(db):
    db.execute("DELETE FROM alert_assets")
    db.execute('UPDATE alerts SET evidence_json=\'{"bucket_classification":"Crítica","hostname":"WS-2"}\'')
    scope = load_db_scopes(db)["A1"]
    assert not scope.assets and not scope.services
