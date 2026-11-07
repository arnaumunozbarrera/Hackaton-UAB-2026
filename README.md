# Hackathon UAB 2026 · Tarvia SOC - AI-assisted L1 triage

Deloitte Cyber AI challenge: a system that triages every alert of the Tarvia SOC, correlates alerts into incidents,
reconstructs attack chains and proposes containment, with a human approving every action.
Challenge brief and dataset: [`docs/README.md`](docs/README.md).

## Repository structure
```
Hackaton-UAB-2026/
├── docs/                 Delivered dataset + challenge docs (READ-ONLY: never edit)
│   ├── 01_contexto/      company, SOC policy, runbooks, output schemas
│   ├── 02_inventario/    CMDB, directory, HR, changes, vulnerabilities
│   ├── 03_alertas/       SIEM alerts
│   ├── 04_logs/          raw logs (18 sources)
│   ├── 05_inteligencia/  TIP, GeoIP, sandbox
│   └── 06_herramientas/  mock SOC API (FastAPI)
├── db/                   Data layer (single SQLite database, hybrid schema)
│   ├── build_db.py       load the dataset -> converts to the hybrid schema
│   ├── migrate_hybrid.py 21 source tables + compatibility views + documents
│   ├── l2_correlate.py   L2: authorised activity, severity matrix, correlation into incidents
│   ├── l3_reconstruct.py L3: attack-chain reconstruction, incident reports
│   ├── catalog.py        generates catalogo_bd.md + schema.sql
│   ├── catalogo_bd.md    data dictionary (generated, versioned)
│   ├── schema.sql        DDL (generated, versioned)
│   └── README.md         layers and rebuild order
├── design/               architecture and data-model diagrams
├── scripts/              setup, rebuild and mock-API helpers (.ps1 Windows / .sh Linux-macOS)
├── tests/                pytest (unit tests + database contract tests)
├── .github/              CI (ruff + pytest) and PR template
├── pyproject.toml        ruff + pytest configuration
└── requirements*.txt     runtime / development dependencies
```
Not versioned (rebuilt locally): `db/tarvia_soc.sqlite` (~1.2 GB), `db/reports/`, `db/enterprise-attack.json`, `.venv/`, `.env`.

## Quick start
Requirements: Python 3.10+ and Git.

**Windows (PowerShell)**
```powershell
git clone https://github.com/arnaumunozbarrera/Hackaton-UAB-2026.git
cd Hackaton-UAB-2026
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1   # .venv + dependencies + pre-commit + MITRE bundle
.\.venv\Scripts\Activate.ps1
scripts\rebuild.ps1                                          # builds db\tarvia_soc.sqlite (~3 min)
pytest
```
**Linux / macOS / Git Bash**
```bash
git clone https://github.com/arnaumunozbarrera/Hackaton-UAB-2026.git && cd Hackaton-UAB-2026
bash scripts/setup.sh && source .venv/bin/activate
bash scripts/rebuild.sh
pytest
```
Mock SOC API (containment with approval tokens): `scripts\mock_api.ps1` or `bash scripts/mock_api.sh` -> http://127.0.0.1:8000/docs

## Pipeline
`alerts + logs -> DB manager (load, similarity, incident grouping) -> discriminator -> prompt builder -> LLM -> validator -> front end (human approval) -> containment API`

| Level | Where | Output |
|---|---|---|
| L1 triage data | `db/build_db.py`, `db/migrate_hybrid.py` | 21 source tables, every record with its original JSON |
| L2 correlation | `db/l2_correlate.py` | `resultado_alerta`, `fact_incident`, `bridge_alert_incident` |
| L3 investigation | `db/l3_reconstruct.py` | `fact_attack_step`, report fields, `db/reports/*.json` |

## Contributing
Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before the first commit: branches, commit format, code rules and review.
