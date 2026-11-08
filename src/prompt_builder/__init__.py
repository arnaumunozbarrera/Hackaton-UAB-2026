"""prompt_builder: parameterised triage prompts for one SIEM alert.

Why: the LLM step needs, for each alert, its identifiers, the affected systems, the runbook (checks, decisions
and the queries that answer each check), the severity policy and only the informative logs selected by
`log_noise_discard`. The LLM reads the database itself, so the prompt identifies rather than copies.

Usage::

    from src.prompt_builder import DatasetContextSource, PromptBuilder

    builder = PromptBuilder(DatasetContextSource("docs"))
    package = builder.build("ALR-20261005-000172")
    messages = package.to_messages()          # [{"role": "system", ...}, {"role": "user", ...}]
    schema = package.response_schema          # ticket_salida.schema.json (structured output)
    tool = package.tool                       # solicitar_contexto(motivo, consultas): response type 2

Live workflow (alerts from the API, stored in the database)::

    source = DatabaseContextSource("data/tarvia.sqlite")
    builder = PromptBuilder(source, runbooks=runbooks_from_db(source.conn))
"""

from .builder import PromptBuilder, PromptConfig, PromptPackage, RenderedQuery
from .context import AlertContext, ContextSource, DatasetContextSource
from .db_context import DatabaseContextSource
from .runbooks import runbooks_from_db
from .schema import QUERIES, SchemaMap
from .tools import TOOL_NAME, connect_read_only, execute, tool_definition

__all__ = [
    "QUERIES", "AlertContext", "ContextSource", "DatabaseContextSource", "DatasetContextSource", "PromptBuilder", "PromptConfig",
    "PromptPackage", "RenderedQuery", "SchemaMap", "TOOL_NAME", "connect_read_only", "execute", "runbooks_from_db",
    "tool_definition",
]  # fmt: skip
