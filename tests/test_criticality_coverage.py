"""Read-only coverage checks against the documented, ingested dataset."""

import sqlite3
from pathlib import Path

import pytest

from src.criticality_scope import load_db_scopes, reviewed_relations
from src.database.enrich import PIPELINE_SQL, VIEWS, _create_alert_tables
from src.database.logs import SPECS
from src.database.schema import SCHEMA_PATH
from src.prompt_builder import DatasetContextSource
from src.prompt_builder.policy import load_policy, most_critical

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data/tarvia.sqlite"
pytestmark = [pytest.mark.integration, pytest.mark.skipif(not DB.exists(), reason="requires ingested dataset")]


@pytest.fixture(scope="module")
def inventory():
    conn = sqlite3.connect(DB.as_uri() + "?mode=ro", uri=True)
    yield conn, load_db_scopes(conn)
    conn.close()


def test_every_alert_has_a_real_inventory_criticality_without_fallback(inventory):
    conn, scopes = inventory
    assets = dict(conn.execute("SELECT hostname,criticality FROM assets"))
    services = dict(conn.execute("SELECT name,criticality FROM business_services"))
    assert len(scopes) == conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
    missing = [
        aid
        for aid, scope in scopes.items()
        if most_critical([assets[h] for h in scope.assets] + [services[s] for s in scope.services]) is None
    ]
    assert missing == []
    # Semantic aliases refer to existing inventory entries and never carry invented criticality values.
    for relation in reviewed_relations():
        assert relation["source"]
        assert relation["target"] in (assets if relation["target_type"] == "asset" else services)


def test_dataset_and_sqlite_resolve_the_same_assets_and_services(inventory):
    _, scopes = inventory
    source = DatasetContextSource(ROOT / "docs")
    source._scope_for(next(iter(source.alerts)))
    for aid, scope in scopes.items():
        other = source._scopes[aid]
        assert scope.assets == other.assets, aid
        assert scope.services == other.services, aid


def test_materialized_matrix_uses_complete_scope_for_every_alert(inventory):
    original, scopes = inventory
    # Copy only inventory, alert relations and cited log detail rows, never write to the original database.
    conn = sqlite3.connect(":memory:", uri=True)
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.executescript(PIPELINE_SQL.read_text(encoding="utf-8"))
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("ATTACH DATABASE ? AS original", (DB.as_uri() + "?mode=ro",))
    tables = [
        "assets",
        "users",
        "hr_events",
        "business_services",
        "asset_services",
        "detection_rules",
        "alerts",
        "alert_assets",
        "alert_users",
        "alert_indicators",
        "alert_files",
        "alert_processes",
        "alert_customers",
        "alert_cloud",
        "alert_ai_sessions",
        "alert_events",
    ]
    for table in tables:
        conn.execute(f"INSERT INTO main.{table} SELECT * FROM original.{table}")  # noqa: S608
    conn.execute("INSERT INTO logs SELECT * FROM original.logs WHERE event_id IN (SELECT event_id FROM alert_events)")
    for spec in SPECS.values():
        conn.execute(
            f"INSERT INTO main.{spec.table} SELECT * FROM original.{spec.table} "  # noqa: S608
            "WHERE event_id IN (SELECT event_id FROM alert_events)"
        )
    conn.execute("CREATE VIEW dim_user AS " + VIEWS["dim_user"])
    conn.execute("CREATE VIEW bridge_alert_entity AS " + VIEWS["bridge_alert_entity"])
    conn.execute("CREATE TABLE dim_context(context_key TEXT,reputation TEXT,sandbox_verdict TEXT)")
    _create_alert_tables(conn, ROOT / "docs", False)
    assets = dict(original.execute("SELECT hostname,criticality FROM assets"))
    services = dict(original.execute("SELECT name,criticality FROM business_services"))
    policy = load_policy(ROOT / "docs/01_contexto/politica_soc.md")
    results = conn.execute(
        "SELECT alert_id,rule_severity,asset_criticality,matrix_base_severity FROM alert_enriched"
    ).fetchall()
    assert len(results) == len(scopes)
    for aid, rule, crit, base in results:
        scope = scopes[aid]
        expected = most_critical([assets[h] for h in scope.assets] + [services[s] for s in scope.services])
        assert (crit, base) == (expected, policy.base_severity(rule, expected)), aid
    conn.close()
