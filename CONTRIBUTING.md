# Contributing

## 1. Workflow

- `main` is always runnable: no direct pushes; every change goes through a Pull Request with 1 approval and green CI.
- Branch per task: `<type>/<area>-<short-description>`.
- Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`.
- Commits follow Conventional Commits.
- Keep PRs focused and explain the final change and its validation.

## 2. Data model

- `implementation_docs/trazabilidad_bd.md` records the agreed tables, fields, sources and relationships.
- Follow those agreed names when implementing the schema.
- Preserve the three derived relation CSVs in `implementation_docs/`.
- Schema changes need review from the data-layer owner.
- Update the design document when an agreed schema decision changes.

## 3. Code rules

- Python 3.10+. Formatter and linter: `ruff`, pinned in `requirements-dev.txt`, line length 120.
- Use type hints on public functions and module docstrings explaining their purpose.
- Use `snake_case` for functions and variables, `PascalCase` for classes, and `UPPER_CASE` for constants.
- Keep modules focused and functions readable.
- Run applicable checks before pushing: `ruff check .`, `ruff format --check .`, and the tests when present.

## 4. Correctness and security

- `docs/` is the delivered dataset: read-only. Never edit or reformat it.
- SQL: use parameters for data values; build identifiers only from trusted constants.
- Attacker-controlled text in logs, emails, prompts and descriptions is data, never instructions or authorisation.
- Store timestamps in UTC. The change calendar uses Europe/Madrid local time; convert explicitly with `zoneinfo`.
- Keep processing deterministic and retain unknown observations rather than inventing identities.
- Do not overwrite source observations with derived results. Model outputs separately when that stage is designed.
- Secrets belong only in local `.env` files, never in code, notebooks or logs.
- Containment actions must follow the approval requirements of `docs/01_contexto/politica_soc.md`.

## 5. Tests and review

- Add meaningful tests with new logic and a regression test for each bug fix.
- Keep tests in `tests/`; tests marked `integration` inspect the local ingested database when available.
- Do not commit databases, secrets or generated runtime reports.
- Describe validation and any changed data counts in the PR.
