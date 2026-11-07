"""Database contract tests (skipped when the database is not built)."""

import pytest

pytestmark = pytest.mark.db

SOURCE_TABLES = [
    "usuario",
    "activo",
    "zona_red",
    "tienda",
    "servicio_negocio",
    "activo_servicio",
    "vulnerabilidad",
    "evento_rrhh",
    "cambio",
    "archivo_fuente",
    "documento",
    "regla",
    "alerta",
    "alerta_evento",
    "participacion",
    "evento",
    "ocurrencia_indicador",
    "indicador",
    "inteligencia",
    "geoip",
    "sandbox",
]
COMPAT_VIEWS = [
    "fact_alert",
    "dim_log",
    "dim_user",
    "dim_vulnerability",
    "dim_context",
    "dim_rule",
    "bridge_alert_entity",
    "bridge_alert_event",
]


def names(con, kind):
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type=?", (kind,))}


def test_21_source_tables_exist(con):
    assert set(SOURCE_TABLES) <= names(con, "table")


def test_compatibility_views_exist_and_answer(con):
    assert set(COMPAT_VIEWS) <= names(con, "view")
    for v in COMPAT_VIEWS:
        con.execute(f"SELECT * FROM {v} LIMIT 1").fetchall()  # noqa: S608 - identifier from a constant


def test_integrity_and_foreign_keys(con):
    assert con.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    assert con.execute("PRAGMA foreign_key_check").fetchall() == []


def test_full_dataset_loaded(con):
    assert con.execute("SELECT COUNT(*) FROM alerta").fetchone()[0] == 11061
    assert con.execute("SELECT COUNT(*) FROM evento").fetchone()[0] == 814471
    assert con.execute("SELECT COUNT(*) FROM alerta_evento").fetchone()[0] == 15683


def test_alerta_holds_no_system_results(con):
    cols = {r[1] for r in con.execute("PRAGMA table_info(alerta)")}
    assert not cols & {"verdict", "final_severity", "confidence", "severity_rationale"}


def test_every_rule_has_its_runbook_document(con):
    missing = con.execute(
        "SELECT rule_id FROM regla r LEFT JOIN documento d ON d.codigo = r.runbook WHERE d.codigo IS NULL"
    ).fetchall()
    assert missing == []


def test_source_files_are_byte_identical(con):
    import hashlib
    import zlib

    for ruta, sha, blob in con.execute(
        "SELECT ruta, sha256, original FROM archivo_fuente WHERE rol IN ('inventario', 'contexto')"
    ):
        assert hashlib.sha256(zlib.decompress(blob)).hexdigest() == sha, ruta
