"""Database backend for `solicitar_contexto`: the catalogue queries run on SQLite, read-only.

Why: same contract as `DatasetToolBackend.execute`, but every query is the parameterised SQL of
`prompt_builder.schema.QUERIES` over the views created by `database.enrich`. Connections are opened in
read-only mode (URI `mode=ro`), one per thread, so the LLM can never write.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

from ..prompt_builder import QUERIES
from ..prompt_builder.tools import execute

# Parameter names whose values are normalised to the stored form before binding.
_LOWER = {"indicator", "sha256"}


def normalise_identity(value: str) -> str:
    return value.lower().split("\\")[-1].split("@")[0]


class DbToolBackend:
    def __init__(self, db_path: str | Path) -> None:
        self.path = Path(db_path).resolve()
        if not self.path.exists():
            raise FileNotFoundError(f"Database not found: {self.path}")
        self._local = threading.local()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, check_same_thread=False)
            self._local.conn = conn
        return conn

    @staticmethod
    def normalise(consulta: str, parametros: list[Any]) -> list[str]:
        names = QUERIES[consulta].params if consulta in QUERIES else ()
        out = []
        for name, value in zip(names, parametros, strict=False):
            text = str(value).strip()
            if name == "user_key":
                text = normalise_identity(text)
            elif name in _LOWER:
                text = text.lower()
            out.append(text)
        return out + [str(v) for v in parametros[len(names) :]]

    def execute(self, consulta: str, parametros: list[str], allowed: list[str] | None = None) -> list[dict[str, Any]]:
        """Same contract as prompt_builder.tools.execute (catalogue only, `?` bindings, 50 rows)."""
        return execute(self._conn(), consulta, self.normalise(consulta, list(parametros)), allowed=allowed)
