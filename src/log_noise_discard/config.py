"""Tunable thresholds of the log noise filter.

Why: the thresholds came from an iterative analysis and will keep changing; keeping them in one immutable
object makes every run reproducible and lets other pipeline steps pass their own values.
"""

from __future__ import annotations

from dataclasses import dataclass, field

OPEN_TEXT_FIELDS: dict[str, tuple[str, ...]] = {
    "email": ("subject",),
    "dlp": ("file_name", "matches.note"),
    "edr_events": (
        "command_line", "details.decoded", "details.description", "details.payload", "details.reason",
        "details.note", "details.persistence", "details.value",
    ),
    "ad_events": ("details.description",),
    "ai_gateway": ("prompt", "response_summary"),
    "idp_audit": ("details.rule_name", "details.message", "details.app"),
    "cicd_builds": ("details.stdout", "details.message"),
    "cloudtrail": ("requestParameters.policy",),
}  # fmt: skip

ALL_STAGES: tuple[str, ...] = ("N1", "N2", "N3", "N4")


@dataclass(frozen=True)
class NoiseFilterConfig:
    """Parameters of stages N1-N4 (N0 always applies: only logs cited by an alert are loaded)."""

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

    # N4: free-text fields (attacker-writable); an explained log with any of them non-empty stays informative.
    open_text_fields: dict[str, tuple[str, ...]] = field(default_factory=lambda: dict(OPEN_TEXT_FIELDS))

    def is_protected(self, rule_id: str, severity: str) -> bool:
        """True when N3 must keep every log of this rule."""
        return severity in self.protected_severities or rule_id.startswith(self.protected_rule_prefixes)
