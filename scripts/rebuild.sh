#!/usr/bin/env bash
# Rebuild the database and every derived artefact from the delivered dataset.
#   bash scripts/rebuild.sh            full rebuild (about 3 minutes)
#   bash scripts/rebuild.sh --from-l2  keep the loaded data, recompute L2 + L3 + docs
set -euo pipefail
cd "$(dirname "$0")/../db"
if [ -f ../.venv/bin/python ]; then PY=../.venv/bin/python; elif [ -f ../.venv/Scripts/python.exe ]; then PY=../.venv/Scripts/python.exe; else PY=python3; fi

if [ "${1:-}" != "--from-l2" ]; then
  MITRE=(); [ -f enterprise-attack.json ] && MITRE=(--mitre enterprise-attack.json)
  $PY build_db.py --data ../docs --out tarvia_soc.sqlite "${MITRE[@]}"
fi
$PY l2_correlate.py --db tarvia_soc.sqlite
$PY l3_reconstruct.py --db tarvia_soc.sqlite --reports reports
$PY catalog.py --db tarvia_soc.sqlite
$PY migrate_hybrid.py --db tarvia_soc.sqlite --stage docs
echo "Rebuild done: db/tarvia_soc.sqlite"
