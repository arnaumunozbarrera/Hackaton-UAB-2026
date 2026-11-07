"""Read function exposed to the LLM: `consultar_bd(consulta, parametros)`.

Why: putting SQL in the prompt costs ~3.5 KB per alert. Instead the prompt lists function names and their
parameters, and the executor maps each name to a catalogue query that selects only the relevant columns. The
LLM cannot run arbitrary SQL through this tool, results are capped, and values are always bound with `?`.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .schema import QUERIES, SchemaMap

TOOL_NAME = "consultar_bd"
MAX_ROWS = 50


def signature(name: str) -> str:
    """'name(param1, param2)' for the prompt."""
    return f"{name}({', '.join(QUERIES[name].params)})"


def tool_definition(names: list[str] | None = None) -> dict[str, Any]:
    """Provider-neutral function definition (name, description, JSON Schema of the input)."""
    allowed = sorted(names or QUERIES)
    catalogue = "; ".join(f"{signature(n)}: {QUERIES[n].purpose}" for n in allowed)
    return {
        "name": TOOL_NAME,
        "description": f"Lectura de la base de datos del SOC (máx. {MAX_ROWS} filas). Consultas: {catalogue}",
        "input_schema": {
            "type": "object",
            "properties": {
                "consulta": {"type": "string", "enum": allowed},
                "parametros": {"type": "array", "items": {"type": "string"}, "description": "valores en orden"},
            },
            "required": ["consulta", "parametros"],
        },
    }


def execute(
    conn: sqlite3.Connection,
    consulta: str,
    parametros: list[str],
    schema_map: SchemaMap | None = None,
    allowed: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Run one catalogue query (read-only connection expected) and return at most MAX_ROWS rows as dicts."""
    if consulta not in QUERIES or (allowed is not None and consulta not in allowed):
        raise ValueError(f"consulta no permitida: {consulta}")
    spec = QUERIES[consulta]
    if len(parametros) != len(spec.params):
        raise ValueError(f"{signature(consulta)} espera {len(spec.params)} parámetros, recibió {len(parametros)}")
    sql = (schema_map or SchemaMap()).render(spec.sql)
    cur = conn.execute(sql, [str(p) for p in parametros])
    cols = [d[0] for d in cur.description or ()]
    return [dict(zip(cols, row, strict=False)) for row in cur.fetchmany(MAX_ROWS)]


def connect_read_only(path: str) -> sqlite3.Connection:
    """SQLite connection that cannot write (URI mode=ro)."""
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)
