"""Prompt context and runbooks read from the workflow database (live alerts)."""

import pytest

from src.checks import run_checks
from src.database.schema import ROOT
from src.prompt_builder import DatabaseContextSource, PromptBuilder, runbooks_from_db
from src.prompt_builder.runbooks import load_runbooks


@pytest.fixture(scope="module")
def source(ingested_db_path):
    src = DatabaseContextSource(ingested_db_path)
    yield src
    src.close()


def test_db_runbooks_have_checks_decisions_and_rules(source):
    books, files = runbooks_from_db(source.conn), load_runbooks(ROOT / "docs" / "01_contexto" / "runbooks")
    assert set(books) == set(files)
    for rid, book in books.items():
        assert book.checks == files[rid].checks and book.decisions == files[rid].decisions
        assert book.rules.startswith("UC-")


def test_latrodectus_context(source):
    ctx = source.get("ALR-20261009-011791")
    assert (ctx.rule_id, ctx.runbook_id, ctx.rule_severity) == ("UC-EDR-001", "RB-02", "high")
    assert [h.hostname for h in ctx.hosts] == ["WS-BCN-1770"] and [u.user_key for u in ctx.users] == ["marta.puig"]
    assert "aplihartom.com" in ctx.entities["domains"]
    assert [lg.reason for lg in ctx.informative_logs] == ["no explicado"] * 5 and not ctx.set_aside


def test_free_text_and_guard_reasons(source):
    sccm = source.get("ALR-20261005-000301")
    assert [(lg.event_id, lg.reason) for lg in sccm.informative_logs] == [("EDR-0005329", "texto libre, CHG-2026-1031")]
    ot = source.get("ALR-20261009-002231")
    assert ot.informative_logs[0].reason.startswith("guarda Severidad, OT,")
    assert ot.hosts[0].zone == "LOGISTICS-IT"


def test_explained_events_are_set_aside_with_their_reference(source):
    ctx = source.get("ALR-20261008-011833")
    assert not ctx.informative_logs and len(ctx.set_aside["N4"]) == 5
    assert set(ctx.explanations.values()) == {"CHG-2026-1042"}
    assert [s.name for s in ctx.services] == ["Tienda online y app"]  # WAF alert without host entity


def test_remembered_checks_are_reused(ingested_db_path):
    src = DatabaseContextSource(ingested_db_path)
    result = run_checks(src.conn, "ALR-20261009-001917")
    result.unexplained, result.explanations = ["SIGN-0018332"], {}
    src.remember(result)
    assert [lg.reason for lg in src.get("ALR-20261009-001917").informative_logs] == ["no explicado"] * 2
    src.close()


def test_prompt_builds_from_the_database(source):
    builder = PromptBuilder(source, runbooks=runbooks_from_db(source.conn))
    package = builder.build("ALR-20261007-011785")
    assert package.runbook_id == "RB-01" and "ALR-20261007-011785" in package.user
    assert "<datos_no_confiables>" in package.user and package.metadata["informative_logs"] >= 3
    assert {q.name for q in package.queries} >= {"alert_enriched", "ref_activity", "user_activity"}


def test_unknown_alert_raises(source):
    with pytest.raises(KeyError):
        source.get("ALR-NOPE")
