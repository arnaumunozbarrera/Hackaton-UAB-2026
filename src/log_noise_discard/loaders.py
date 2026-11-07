"""Read-only access to the delivered dataset.

Why: the dataset under docs/ must never be modified, so every file is opened for reading only and streamed,
which keeps memory flat even for the 50+ MB sources.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .templates import SourceSpec

ALERTS_FILE = Path("03_alertas") / "alertas.jsonl"
CATALOG_FILE = Path("01_contexto") / "catalogo_casos_de_uso.csv"
LOGS_DIR = Path("04_logs")


def iter_source(data_dir: Path, spec: SourceSpec) -> Iterator[tuple[dict[str, Any], int]]:
    """Yield (event, size_in_bytes) for every event of one log source."""
    path = data_dir / LOGS_DIR / spec.file
    if spec.fmt == "jsonl":
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line), len(line.encode("utf-8"))
        return
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            yield row, sum(len(v or "") for v in row.values()) + len(row)


def load_alerts(data_dir: Path) -> dict[str, dict[str, Any]]:
    """All SIEM alerts keyed by alert_id."""
    alerts: dict[str, dict[str, Any]] = {}
    with (data_dir / ALERTS_FILE).open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                alert = json.loads(line)
                alerts[alert["alert_id"]] = alert
    return alerts


def load_rule_severity(data_dir: Path) -> dict[str, str]:
    """Base severity of each detection rule from the use-case catalogue."""
    with (data_dir / CATALOG_FILE).open(encoding="utf-8", newline="") as fh:
        return {row["rule_id"]: row["severidad_base"] for row in csv.DictReader(fh)}
