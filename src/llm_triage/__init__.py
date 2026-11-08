"""llm_triage: Anthropic connection, read-tool loop, ticket validation and a temporary chat UI.

Why: closes the loop prompt -> LLM -> validated ticket while the database is not ready; the dataset backend
answers the same read functions the database will.

    python -m src.llm_triage serve [--mock | --claude-code]   # chat on http://127.0.0.1:8765
    python -m src.llm_triage triage ALR-... [--mock]
"""

from .backend import DatasetToolBackend
from .claude_code import ClaudeCodeRunner
from .client import AnthropicLLM, MockLLM, TriageResult, TriageRunner, load_env
from .db_backend import DatabaseToolBackend
from .validator import validate_ticket

__all__ = [
    "AnthropicLLM",
    "ClaudeCodeRunner",
    "DatabaseToolBackend",
    "DatasetToolBackend",
    "MockLLM",
    "TriageResult",
    "TriageRunner",
    "load_env",
    "validate_ticket",
]
