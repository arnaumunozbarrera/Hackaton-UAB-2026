"""Deterministic basic checks run on each stored alert before the LLM (workflow step 3).

- `db_events.log_record`: a stored event rebuilt in its raw API shape.
- `db_context.load_context` / `DbFacts` / `ApiFacts`: N4 reference data and facts about other logs.
- `rules.run_checks`: close (with a verdict) or keep, plus the guards and per-event explanations.
- `ticket.auto_ticket`: the ticket for a closed alert (same schema as the LLM ticket).
"""

from .db_context import ApiFacts, DbFacts, load_context
from .rules import CheckResult, run_checks
from .ticket import auto_ticket, load_ticket_schema

__all__ = ["ApiFacts", "CheckResult", "DbFacts", "auto_ticket", "load_context", "load_ticket_schema", "run_checks"]
