#!/usr/bin/env bash
# One-time developer setup (Linux / macOS / Git Bash).  Run from the repository root: bash scripts/setup.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PY=${PYTHON:-python3}
$PY -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ is required"'

[ -d .venv ] || $PY -m venv .venv
if [ -f .venv/bin/python ]; then VPY=.venv/bin/python; else VPY=.venv/Scripts/python.exe; fi
$VPY -m pip install --upgrade pip
$VPY -m pip install -r requirements-dev.txt
$VPY -m pre_commit install

[ -f .env ] || cp .env.example .env

MITRE=db/enterprise-attack.json
if [ ! -f "$MITRE" ]; then
  echo "Downloading MITRE ATT&CK Enterprise bundle..."
  curl -fsSL -o "$MITRE" https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
fi
echo "Setup done. Activate with: source .venv/bin/activate   then build with: bash scripts/rebuild.sh"
