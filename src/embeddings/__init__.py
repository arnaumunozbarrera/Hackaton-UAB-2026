"""Alert representations and local embedding generation for the Tarvia SOC."""

from .canonical import canonical_alert_text, load_alerts
from .log_context import (
    SelectedLog,
    collect_dataset_candidates,
    collect_dataset_candidates_for_alerts,
    log_context_text,
    select_log_context,
)

__all__ = [
    "SelectedLog",
    "canonical_alert_text",
    "collect_dataset_candidates",
    "collect_dataset_candidates_for_alerts",
    "load_alerts",
    "log_context_text",
    "select_log_context",
]
