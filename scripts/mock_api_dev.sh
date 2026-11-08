#!/usr/bin/env bash
# Start the simulated SOC API for development (http://127.0.0.1:8000/docs).
# Serves the 20-alert debug feed (TARVIA_MOCK_ALERTS=all for the full queue) and writes containment to data/.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .venv/bin/python ]; then PY=.venv/bin/python; else PY=python3; fi
exec $PY -m uvicorn src.dev.mock_api:app --port "${TARVIA_MOCK_PORT:-8000}"
