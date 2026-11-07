#!/usr/bin/env bash
# Start the simulated SOC API (http://127.0.0.1:8000/docs)
set -euo pipefail
cd "$(dirname "$0")/../docs/06_herramientas"
if [ -f ../../.venv/bin/python ]; then PY=../../.venv/bin/python; else PY=python3; fi
exec $PY -m uvicorn mock_soc_api:app --port 8000
