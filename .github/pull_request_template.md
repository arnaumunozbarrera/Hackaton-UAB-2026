## What and why
<!-- One or two sentences. Link the Asana / issue task if any. -->

## Area
- [ ] db (load / schema)  - [ ] L2 correlation  - [ ] L3 investigation  - [ ] LLM / prompt  - [ ] front end  - [ ] docs

## Checklist
- [ ] `ruff check .` and `ruff format --check .` pass (pre-commit does it)
- [ ] Applicable tests pass; new logic has a test
- [ ] No database, `.env`, API key or generated report committed
- [ ] `docs/` (delivered dataset) not modified
- [ ] Data-model change? `implementation_docs/trazabilidad_bd.md` reflects the agreed fields, sources and relations
- [ ] Any implemented data processing is reproducible and its checks are described
