"""Dev wrapper of the delivered mock SOC API: smaller alert queue and containment log outside docs/.

The delivered API (docs/06_herramientas/mock_soc_api.py, read-only) serves all 11,061 alerts and appends executed
containment to docs/06_herramientas/containment_log.jsonl, which would write into the read-only dataset. This wrapper
imports it unchanged and overrides two module globals the endpoints read at call time:
- ALERTS: the file in TARVIA_MOCK_ALERTS (default dev/alertas_debug.jsonl); `all` keeps the full dataset;
- LOGFILE: TARVIA_CONTAINMENT_LOG (default data/containment_log.jsonl);
- logs: with TARVIA_MOCK_LOGS=dev/alertas_debug_events.jsonl, GET /logs/{source} serves only those rows (fast
  start, fully self-contained test); unset = the full docs/04_logs.

Run: uvicorn src.dev.mock_api:app --port 8000  (or bash scripts/mock_api_dev.sh)
"""

import importlib.util
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MOCK_PATH = ROOT / "docs" / "06_herramientas" / "mock_soc_api.py"
DEFAULT_ALERTS = ROOT / "dev" / "alertas_debug.jsonl"
DEFAULT_LOG = ROOT / "data" / "containment_log.jsonl"


def _load_mock():
    spec = importlib.util.spec_from_file_location("mock_soc_api", MOCK_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {MOCK_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _resolve(value: str | None, default: Path) -> Path:
    path = Path(value) if value else default
    return path if path.is_absolute() else ROOT / path


mock = _load_mock()
alerts_setting = os.environ.get("TARVIA_MOCK_ALERTS", "")
if alerts_setting.lower() != "all":
    alerts_path = _resolve(alerts_setting, DEFAULT_ALERTS)
    with alerts_path.open(encoding="utf-8") as stream:
        mock.ALERTS = {a["alert_id"]: a for a in (json.loads(line) for line in stream if line.strip())}
logs_setting = os.environ.get("TARVIA_MOCK_LOGS", "")
if logs_setting:
    # Serve GET /logs/{source} only from this file ({"source", "row"} lines, e.g. dev/alertas_debug_events.jsonl)
    # by pre-filling the API's per-source cache; every known source starts empty so docs/04_logs is never read.
    sources = {p.stem for p in Path(mock.LOGDIR).iterdir() if p.suffix in (".jsonl", ".csv")}
    mock._cache.update({source: [] for source in sources})
    with _resolve(logs_setting, ROOT / "dev" / "alertas_debug_events.jsonl").open(encoding="utf-8") as stream:
        for item in (json.loads(line) for line in stream if line.strip()):
            mock._cache.setdefault(item["source"], []).append(item["row"])
log_path = _resolve(os.environ.get("TARVIA_CONTAINMENT_LOG"), DEFAULT_LOG)
log_path.parent.mkdir(parents=True, exist_ok=True)
mock.LOGFILE = str(log_path)
app = mock.app
