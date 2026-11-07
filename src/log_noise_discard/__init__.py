"""log_noise_discard: select only the informative logs cited by SIEM alerts.

Why: the triage steps (context package, LLM, correlation) should receive logs that help decide and prioritise
an alert, not repeated or non-discriminant ones. This package applies the noise stages N0-N3 as a read-only
selection over the dataset: no file is modified or deleted.

Usage from another step::

    from src.log_noise_discard import NoiseFilterConfig, run_filter

    result = run_filter("docs")
    logs = result.kept_for_alert("ALR-20261005-000172")
"""

from .config import NoiseFilterConfig
from .pipeline import FilterResult, StageStat, run_filter
from .stages import LogRecord, NoiseGroup

__all__ = ["FilterResult", "LogRecord", "NoiseFilterConfig", "NoiseGroup", "StageStat", "run_filter"]
