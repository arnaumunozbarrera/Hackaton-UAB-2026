"""Simulated SOC API serving a chosen alerts file, on top of docs/06_herramientas/mock_soc_api.py (unchanged).

Why: docs/ is read-only and the provided mock always serves docs/03_alertas/alertas.jsonl. This wrapper imports
the mock as it is and swaps only its alert store, so the SOC "receives" a new batch of alerts; every other
endpoint (assets, users, logs, intelligence, approvals, containment) keeps reading the dataset. The containment
log is written under data/ instead of docs/.

    $env:TARVIA_ALERTS_FILE = "data/demo_alertas_comunes.jsonl"
    python -m uvicorn src.demo_api:app --port 8000
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "docs" / "06_herramientas"


def load_alerts(path: Path) -> dict[str, dict]:
    with path.open(encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    return {a["alert_id"]: a for a in sorted(rows, key=lambda a: a["created_at"])}


def alerts_file() -> Path:
    path = Path(os.environ.get("TARVIA_ALERTS_FILE") or ROOT / "data" / "demo_alertas_comunes.jsonl")
    return path if path.is_absolute() else ROOT / path


sys.dont_write_bytecode = True  # do not leave __pycache__ inside docs/
sys.path.insert(0, str(TOOLS))
mock = importlib.import_module("mock_soc_api")
mock.ALERTS.clear()
mock.ALERTS.update(load_alerts(alerts_file()))
mock.LOGFILE = str(ROOT / "data" / "containment_log.jsonl")
app = mock.app
print(f"[demo_api] serving {len(mock.ALERTS)} alerts from {alerts_file()}")
