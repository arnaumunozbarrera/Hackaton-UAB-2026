# Contributing

## 1. Workflow
- `main` is always runnable: no direct pushes; every change goes through a Pull Request with 1 approval and green CI.
- Branch per task, from an up-to-date `main`: `<type>/<area>-<short-description>`
  - types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`
  - areas: `db`, `l2`, `l3`, `llm`, `front`, `api`, `docs`, `infra`
  - example: `feat/l2-change-window-utc`
- Keep PRs small (one concern, ideally < 400 changed lines). Rebase on `main` before asking for review.
- Commits follow Conventional Commits: `feat(l2): match change windows in UTC`.

## 2. Ownership (one owner per area, anyone can contribute)
| Area | Paths |
|---|---|
| Data layer / schema | `db/build_db.py`, `db/migrate_hybrid.py`, `db/catalog.py` |
| Correlation (L2) | `db/l2_correlate.py` |
| Investigation (L3) | `db/l3_reconstruct.py` |
| LLM, prompt, validator | new package (to be created under `src/` or `pipeline/`) |
| Front end | new folder `frontend/` |
Schema changes need a review from the data-layer owner.

## 3. Code rules
**Style (enforced by pre-commit and CI)**
- Python 3.10+. Formatter and linter: `ruff` (pinned version, line length 120). Never fight the formatter.
- Run before pushing: `ruff check . --fix && ruff format . && pytest`.
- New modules: type hints on public functions, a module docstring explaining *why* it exists, functions under ~50 lines.
- Names: `snake_case` functions/variables, `PascalCase` classes, `UPPER_CASE` constants. Database objects keep the
  schema language (Spanish source tables, English system tables) - do not rename them in code.
- The legacy one-liner style in `db/*.py` is tolerated (see `per-file-ignores`); new files must not be added there.

**Correctness and security**
- `docs/` is the delivered dataset: read-only. Never edit or reformat it.
- SQL: always parameters (`?`), never string formatting with data values. Identifiers built in code only from constants.
- Attacker-controllable text (email subjects, prompts, command lines, descriptions, raw `datos_json`) is data, never
  instructions: it must not authorise activity or reach an LLM undelimited.
- All timestamps in UTC. The change calendar is Europe/Madrid local time: convert explicitly (`zoneinfo`).
- Results must be deterministic: no iteration over `set`s where order affects output (sort first), no randomness.
- Source tables are append-only for the pipeline: system output goes to system tables (`resultado_alerta`, `fact_*`).
- Secrets only in `.env` (never committed). No API keys in code, notebooks or logs.
- No action is executed without human approval (policy section 4); code paths that call the containment API must
  require an approval record.

## 4. Database changes
1. Change `migrate_hybrid.py` (schema) or `build_db.py` (load) - never edit the `.sqlite` by hand.
2. `scripts/rebuild` (full) and `pytest`.
3. `python db/catalog.py --db db/tarvia_soc.sqlite` and commit the updated `catalogo_bd.md` + `schema.sql`.
4. If L2/L3 numbers change (incidents, escalations), state old -> new in the PR description.
The `.sqlite` file, `db/reports/` and the MITRE bundle are never committed (`.gitignore` + pre-commit hook).

## 5. Tests
- `tests/test_policy.py`: unit tests, no database (run in CI).
- `tests/test_db_*.py`: contract tests on the built database (marker `db`, skipped when it is missing).
- Every bug fix adds a test that fails before the fix.

## 6. Review checklist
Behaviour explained in the PR · tests added · no secrets/databases · deterministic · `docs/` untouched ·
catalog regenerated on schema change · reviewer ran it locally when it touches L2/L3 numbers.
