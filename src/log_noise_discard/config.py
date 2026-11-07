"""Tunable thresholds of the log noise filter.

Why: the thresholds came from an iterative analysis and will keep changing; keeping them in one immutable
object makes every run reproducible and lets other pipeline steps pass their own values.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ALL_STAGES: tuple[str, ...] = ("N1", "N2", "N3")


@dataclass(frozen=True)
class NoiseFilterConfig:
    """Parameters of stages N1-N3 (N0 always applies: only logs cited by an alert are loaded)."""

    stages: tuple[str, ...] = ALL_STAGES
    # N3: a template is non-discriminant when it appears in >= tau of the alerts of a rule ...
    tau: float = 0.8
    # ... and the rule has at least this many alerts.
    min_rule_alerts: int = 5
    # N3 never discards logs of rules with these base severities (mandatory escalation in the SOC policy).
    protected_severities: tuple[str, ...] = ("high", "critical")
    # N3 never discards logs of rules with these prefixes (OT: any action needs the Operations owner).
    protected_rule_prefixes: tuple[str, ...] = ("UC-OT-",)
    # N3 keeps these fields of discarded logs in the group summary because they vary between alerts.
    varying_fields: dict[str, tuple[str, ...]] = field(default_factory=lambda: {"ai_gateway": ("prompt",)})

    def is_protected(self, rule_id: str, severity: str) -> bool:
        """True when N3 must keep every log of this rule."""
        return severity in self.protected_severities or rule_id.startswith(self.protected_rule_prefixes)
