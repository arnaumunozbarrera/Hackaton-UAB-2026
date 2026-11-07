## What and why
<!-- One or two sentences. Link the Asana / issue task if any. -->

## Area
- [ ] db (load / schema)  - [ ] L2 correlation  - [ ] L3 investigation  - [ ] LLM / prompt  - [ ] front end  - [ ] docs

## Checklist
- [ ] `ruff check .` and `ruff format --check .` pass (pre-commit does it)
- [ ] `pytest` passes; new logic has a test
- [ ] No database, `.env`, API key or generated report committed
- [ ] `docs/` (delivered dataset) not modified
- [ ] Schema change? `catalog.py` re-run and `catalogo_bd.md` / `schema.sql` updated in this PR
- [ ] Results reproducible: `scripts/rebuild` run, numbers in the description (incidents / escalations) if they changed
