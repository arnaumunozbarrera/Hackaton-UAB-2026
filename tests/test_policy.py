"""Unit tests (no database needed): policy and helpers stay consistent with the delivered documentation."""

import re

from db import build_db, l2_correlate, migrate_hybrid
from tests.conftest import ROOT


def test_severity_matrix_matches_policy_document():
    """build_db.MATRIX must be exactly the table of politica_soc.md section 2."""
    text = (ROOT / "docs" / "01_contexto" / "politica_soc.md").read_text(encoding="utf-8")
    text = text[text.index("## 2.") : text.index("## 3.")]  # only the severity matrix section
    rows = re.findall(r"^\| (informational|low|medium|high|critical) \|(.+)\|$", text, re.M)
    assert len(rows) == 5
    for rule_sev, cells in rows:
        assert [c.strip() for c in cells.split("|")] == build_db.MATRIX[rule_sev]


def test_user_normalisation():
    for raw in ("TARVIA\\Marta.Puig", "marta.puig@tarvia.example", "MARTA.PUIG"):
        assert build_db.norm_user(raw) == "marta.puig"
        assert migrate_hybrid.nuser(raw) == "marta.puig"


def test_change_calendar_is_local_time():
    """Change windows are Madrid local time: 10:00 CEST = 08:00 UTC, 10:00 CET (after 25-Oct) = 09:00 UTC."""
    assert l2_correlate.local_to_utc("2026-10-13 10:00").hour == 8
    assert l2_correlate.local_to_utc("2026-10-27 10:00").hour == 9


def test_indicator_typing_and_normalisation():
    assert migrate_hybrid.ind_type("10.10.3.95") == "ip"
    assert migrate_hybrid.ind_type("aplihartom.com") == "domain"
    assert migrate_hybrid.ind_type("https://x.example/a") == "url"
    assert migrate_hybrid.ind_type("a" * 64) == "sha256"
    assert migrate_hybrid.Idx.norm("domain", "ApliHartom.COM") == ("aplihartom.com", "aplihartom.com")
