"""triage_flow: the end-to-end Tarvia SOC triage pipeline over the database.

ingestion (database.sync) -> enrich (database.enrich) -> log selection (log_noise_discard, persisted)
-> discriminator (skip the LLM when every cited log is explained by context) -> embeddings (similar resolved
alerts) -> prompt (prompt_builder.DbContextSource) -> LLM (llm_triage) -> validated ticket (triage_tickets)
-> operator decision (front) -> alert_history.
"""

from .flow import TriageFlow

__all__ = ["TriageFlow"]
