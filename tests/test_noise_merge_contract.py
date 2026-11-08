"""Keep the imported filter compatible with the database's complete event sources."""

import pytest

from src.database.logs import SPECS
from src.database.schema import ROOT
from src.log_noise_discard import NoiseFilterConfig, run_filter
from src.log_noise_discard.__main__ import _guard_output
from src.log_noise_discard.templates import SOURCES


def test_both_modules_cover_the_same_original_log_sources():
    assert set(SPECS) == set(SOURCES)
    for source, spec in SOURCES.items():
        assert spec.file == source + (".csv" if source in {"dns", "proxy", "firewall"} else ".jsonl")


def test_noise_export_cannot_overwrite_the_original_dataset(tmp_path):
    data = tmp_path / "docs"
    data.mkdir()
    with pytest.raises(SystemExit, match="read-only dataset"):
        _guard_output(data / "04_logs" / "email.jsonl", data)
    _guard_output(tmp_path / "selection.jsonl", data)


@pytest.mark.integration
def test_imported_filter_preserves_its_documented_full_dataset_results():
    if not (ROOT / "docs/03_alertas/alertas.jsonl").exists():
        pytest.skip("Original dataset unavailable")
    result = run_filter(ROOT / "docs", NoiseFilterConfig())
    assert [(stage.stage, stage.discarded_events, stage.remaining_events) for stage in result.stats] == [
        ("N0", 798821, 15650),
        ("N1", 2733, 12917),
        ("N2", 11, 12906),
        ("N3", 1760, 11146),
        ("N4", 6000, 5146),
    ]
    assert set(result.kept).isdisjoint(result.discarded)
    assert len(result.kept) + len(result.discarded) == 15650
    assert all(event in result.kept for events in result.alert_events.values() for event in events)
