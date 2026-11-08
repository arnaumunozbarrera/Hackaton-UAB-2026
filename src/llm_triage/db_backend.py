"""Answer the LLM's context requests (`solicitar_contexto`) with catalogue queries on a read-only SQLite connection.

Why: the dataset backend scans docs/ (1-5 s per call) and cannot see alerts that arrive through the API. This one
runs the named queries of `prompt_builder.schema.QUERIES` against TARVIA_DB opened with `mode=ro`, so the model can
only read, only through the catalogue, with `?` parameters and at most 50 rows per query.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

from ..database.schema import ROOT
from ..prompt_builder.tools import connect_read_only, execute


def default_db_path() -> Path:
    return Path(os.environ.get("TARVIA_DB") or ROOT / "data" / "tarvia.sqlite")


class DatabaseToolBackend:
    """Same contract as DatasetToolBackend.execute, backed by the database."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.path = Path(db_path) if db_path else default_db_path()
        if not self.path.exists():
            raise FileNotFoundError(f"Database not found: {self.path}")
        self.conn = connect_read_only(str(self.path.resolve()))
        self.conn.execute("PRAGMA query_only = ON")

    def execute(self, consulta: str, parametros: list[str], allowed: list[str] | None = None) -> list[dict[str, Any]]:
        try:
            return execute(self.conn, consulta, parametros, allowed=allowed)
        except sqlite3.Error as exc:
            raise ValueError(f"error en la consulta {consulta}: {exc}") from exc

    def close(self) -> None:
        self.conn.close()
