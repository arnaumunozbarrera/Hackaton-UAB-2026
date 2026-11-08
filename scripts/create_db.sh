#!/usr/bin/env bash
# Create and ingest the agreed SQLite model from the repository sources.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .venv/bin/python ]; then
  python_executable=.venv/bin/python
elif [ -f .venv/Scripts/python.exe ]; then
  python_executable=.venv/Scripts/python.exe
else
  python_executable=${PYTHON:-python3}
fi
exec "$python_executable" -m src.database.build "$@"
