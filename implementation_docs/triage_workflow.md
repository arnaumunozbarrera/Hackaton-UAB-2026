# L1 triage workflow: implementation log and handoff

Companion of the build plan (`L1 triage workflow`, kept in Cursor plans). One entry per finished step: what was done,
files changed, deviations and open issues. Read this first when picking the work up.

## Decisions (agreed with the user)

- Only new alerts from the SOC API are processed. The workflow database is built **context only** (no alerts, no
  logs); each alert brings its own logs through the API.
- Development uses a 20-alert debug feed (`dev/alertas_debug.jsonl`) served by `scripts/mock_api_dev.sh`.
- UI: `frontend/` (Sentinel design) on real data. `src/llm_triage/server.py` + `chat.html` are kept as legacy.
- LLM: `--llm anthropic` (API key) or `--llm claude-code` (subscription); `openai` for an OpenAI-compatible cluster endpoint; `mock` for tests; `none` = checks only.
- Result tables live in the generated schema (`trazabilidad_bd.md` + `model.json` -> `schema.py` -> `schema.sql`).

## Progress log

### Step 0. Baseline and dev environment

- `.venv` was missing `jsonschema`, `anthropic`, `claude-agent-sdk`, `httpx`...: installed with pip (the heavy
  embedding stack, `sentence-transformers`/`umap-learn`, is not needed for the workflow). Baseline: 58 tests green.
- Lint/format fixes in `src/embeddings/*` and `tests/test_embeddings.py` (pre-existing ruff errors).
- `src/llm_triage/claude_code.py`: `ClaudeCodeRunner` now accepts and stores `max_context_requests` (was an
  `AttributeError` on every run).
- `src/llm_triage/context_requests.py`: each transcript entry of type `contexto` now also carries `resultados`
  (the rows returned per query), so the workflow can store and show them.
- `scripts/make_debug_alerts.py` -> `dev/alertas_debug.jsonl`: 20 alerts, all runbooks, the 3 reference alerts,
  auto-close candidates and guard cases (selection and reasons in `DEBUG_ALERTS`).
- `src/dev/mock_api.py` + `scripts/mock_api_dev.sh`: the delivered mock API unchanged, with `ALERTS` replaced by the
  debug feed (`TARVIA_MOCK_ALERTS`, `all` = full queue) and `LOGFILE` moved to `data/containment_log.jsonl`
  (the original writes into `docs/`, which is read-only).
- `frontend/app.js` duplicate definitions are removed in Step 8 (the file is rewritten there).

### Step 1. Context-only database build

- `python -m src.database.build --context-only` (`bash scripts/create_db.sh --context-only --replace`): loads
  inventory, intelligence, rules and runbooks only (~3 s). The ingestion report records `"mode": "context_only"`.
- `src/database/validation.py`: `observation_table()` (logs group, `alerts`, `alert_*`) must be empty in this mode
  and its documented distinct counts are skipped; every other check is unchanged.
- `changes.start_at/end_at` are stored in UTC (converted from Europe/Madrid by `core.timestamp(local=True)`).
- Verified: the 20 debug alerts and their 36 log events ingest through `python -m src.main` into a context-only DB
  (the `email_clicks` -> parent email path works with an empty `email_logs`).
- Tests: `test_context_only_build_has_inventory_but_no_alerts_or_logs`; the integration tests on
  `data/tarvia.sqlite` skip when that file is a context-only build.

### Step 2. Result tables (generated schema)

- Six tables in the new `triage` group, documented in `implementation_docs/trazabilidad_bd.md` (end of file) and
  added to `implementation_docs/diagrams/model.json` (62 tables now); `schema.sql` regenerated with
  `python -m src.database.schema`. The diagrams (SVG/drawio/HTML) are produced by an external tool and are stale
  (noted in `implementation_docs/diagrams/README.md`).
- **Deviation:** `triage_tickets` is keyed by `run_id`, not `ticket_id`: the model chooses `ticket_id` and it may
  repeat across alerts. `analyst_decisions.run_id` and `executed_actions.run_id` reference `triage_tickets.run_id`.
- `src/database/schema.py`: `REAL_FIELDS`, `ENUMS` (closed domains -> CHECK), `REQUIRED` (NOT NULL pairs), new
  boolean/integer names, `ticket_confidence` 0-1 CHECK, `analyst_decisions.item` CHECK (`verdict` | `action:<n>`).
  `run_id`, `decision_id`, `execution_id` are `INTEGER PRIMARY KEY` (auto-increment rowid aliases).
- `validation.counts_and_distinct`: every `triage` table must be empty after a build.
- An existing `data/tarvia.sqlite` built before this step lacks the tables: rebuild it
  (`bash scripts/create_db.sh --context-only --replace`).
- Tests: `tests/test_triage_schema.py`. A full build (`python -m src.database.build`) still validates.

### Step 3. Query catalogue on the real schema + `DatabaseToolBackend`

- `src/prompt_builder/schema.py` rewritten: the same 21 query names, purposes and parameters, written for
  `schema.sql`. Cross-source log queries read `LOG_VIEW`, a UNION ALL generated from the trusted constant
  `LOG_PROJECTION` (per source: which column is user, host, src_ip, dst, action, result, ref_id, sha256,
  customer_id). `log_detail` returns the whole detail row as JSON (columns taken from `model.json`), plus email
  recipients/urls/attachments and AI tool calls. `severity_matrix` is a constant VALUES table (policy §2).
  `incident_links` returns a fixed "correlation out of scope" row.
- Parameters use numbered placeholders (`?1`, `?2`...) so a value can be reused; `tools.execute` binds them as a
  mapping (`{"1": ...}`), since binding a list to `?N` is deprecated in Python 3.12 and an error in 3.14.
- `changes_in_window` parameters are now `(window_start, window_end)` (the old order was reversed).
- `SchemaMap` remains (placeholders still render) but the catalogue uses physical names.
- `src/llm_triage/db_backend.py::DatabaseToolBackend(db_path)`: read-only (`mode=ro` + `PRAGMA query_only`),
  SQLite errors become `ValueError` so the LLM gets them as a tool error.
- `tests/conftest.py`: `ReplayApi` (fake SOC API over the debug feed), `context_db_path` (session context-only build),
  `ingested_db_path` (debug alerts ingested), `mini_db` (writable per-test copy). `scripts/make_debug_alerts.py` now
  also writes `dev/alertas_debug_events.jsonl` (raw rows of the cited logs) for that replay.
- Tests: `tests/test_query_catalogue.py`; `tests/test_prompt_builder.py` updated to the new contract.
- Known limitation: in a context-only DB the activity queries only see logs of alerts already ingested.

### Step 4. Basic checks on database data (`src/checks/`)

- `db_events.log_record(conn, event_id)`: rebuilds the raw API event from `logs` + detail table + child tables by
  reversing `src.database.logs.SPECS` (users written as UPN / `TARVIA\user` / username as each source does, CSV
  sources as strings). Round trip is exact for every debug event (test).
- `db_context.load_context(conn)`: the N4 `Context` (TIP, GeoIP, sandbox, assets, changes in UTC, HR trips and
  leavers) from DB tables. Facts about other logs: `DbFacts` (stored logs) and `ApiFacts` (DB + `GET /logs/{source}`
  search via the new `SocApi.search_logs`). **Use `ApiFacts` in the workflow**: with a context-only DB, "scanner never
  got a 2xx" and "known device" can only be proved on all logs. Facts can only keep alerts, never close more.
- `rules.run_checks(conn, alert_id, base=, facts=)` -> `CheckResult` (discard, verdict, severity, reasons,
  references, guards, explanations per event, open_text, unexplained, sources). Reuses the validated N4 matchers
  (`explain_log`, `_travel_explained`, `has_open_text`, `_has_bad_indicator`). Closed only if every cited event is
  explained, no explained event has free text, and no guard: high/critical rule or alert; OT (asset zone, UC-OT-*,
  firewall to OT); G1 TIP malicious/suspicious in entities/evidence/events; G2 another unexplained high/critical
  alert sharing user/asset/indicator/customer within ±24 h ("explained" = closed by the checks or by an analyst as
  benign/false positive); no or missing events. Verdict: any A/B/F category -> `benign_true_positive`, else
  `false_positive`; severity `informational` with an approved change, else `low`.
- `ticket.auto_ticket(conn, result)`: schema-valid ticket (`TKT-AUTO-<id>`), confidence 0.9, no actions, no
  escalation.
- Debug feed results (with API facts): 8 auto-closed (000440, 011833, 001917, 011873, 011851, 011922, 009418,
  002565), 12 kept. `make_debug_alerts.py` adds "context" sign-in rows (same device, not cited) so `ReplayApi`
  can prove the known device offline; `ReplayApi.search_logs` added.
- G2 limitation: alerts are processed in time order, so only earlier (or already stored) alerts can block.
- Tests: `tests/test_checks.py`.

### Step 4. Basic checks on database data (`src/checks/`)

- `db_events.log_record(conn, event_id)`: rebuilds the raw API event from `logs` + detail table + child tables by
  reversing `src.database.logs.SPECS` (user written as UPN / `TARVIA\user` / username depending on the source; CSV
  sources as strings). Verified identical to the raw rows of every debug event (`test_stored_events_rebuild...`).
- `db_context.load_context(conn)`: the N4 `Context` (TIP, GeoIP, sandbox, assets, changes in UTC, HR trips/leavers)
  from DB tables. Facts about *other* logs (scanner IP ever got a 2xx / e-commerce success; devices a user signs in
  from outside Private Relay) come from `DbFacts` (stored logs) or `ApiFacts` (DB + `GET /logs/{source}?q=`; new
  `SocApi.search_logs`). **Use `ApiFacts` in the workflow**: with a context-only DB, absence in the DB proves nothing.
- `rules.run_checks(conn, alert_id, base=, facts=)` -> `CheckResult(discard, verdict, severity, reasons,
  references, guards, explanations, open_text, unexplained, sources)`. Reuses `explain_log` (A-E) and the
  UC-IDP-001 travel rule (F) unchanged. Closes only if every cited event is explained, none has open text, and no
  guard fires: rule/alert severity high|critical, OT (LOGISTICS-OT asset, UC-OT-*, firewall towards OT), G1 (TIP
  malicious/suspicious in entities/evidence/events), G2 (another high/critical alert sharing user/asset/indicator/
  customer within ±24 h, not closed by checks nor by an analyst as FP/BTP), no events / missing events.
  Verdict: benign_true_positive if any A/B/F category, else false_positive; severity informational if an approved
  change (A) explains it, else low.
- `ticket.auto_ticket(conn, result)`: schema-valid ticket, no actions, no escalation, confidence 0.9,
  `ticket_id = TKT-AUTO-<alert suffix>`.
- Debug feed result (with API facts): 8 of 20 auto-close (scanner, pentest, Private Relay, HR trip, NESSUS,
  Logisoft change, sandbox clean, benign domain); the rest go to the LLM.
- `scripts/make_debug_alerts.py` also writes up to 3 earlier same-device sign-ins per cited sign-in (`"context":
  true`) so `ReplayApi.search_logs` can prove the "known device" fact offline.
- Limitation: G2 only sees alerts already ingested (sequential processing, no look-ahead).
- Tests: `tests/test_checks.py`.

### Step 5. Prompt context from the database

- `src/prompt_builder/db_context.py::DatabaseContextSource(db_path)`: same `AlertContext` as the dataset source,
  read (read-only connection) from `alerts`, `alert_*`, `assets`, `users`, `hr_events`, `business_services`.
  Informative logs come from the alert's `CheckResult` (pass it with `source.remember(result)`; otherwise the
  checks are re-run with DB-only facts): no guard -> explained events without free text are set aside (`N4`, with
  reference); guard -> every event is informative with reason `guarda <codes>, <reference>`. N1-N3 (dataset-wide)
  do not apply to live alerts.
- `runbooks.runbooks_from_db(conn)` (checks/decisions parsed from `runbooks`, rules from `detection_rules`);
  `PromptBuilder(source, runbooks=...)`. Policy and ticket schema are still read from `docs/` (read-only).
- Tests: `tests/test_db_context.py` (DB runbooks equal the markdown ones; Latrodectus, SCCM, OT, pentest contexts).

### Step 6. Orchestration, storage and CLI (`src/workflow/`, `src/main.py`)

- `workflow/store.py`: WAL connection; `start_run`/`finish_run` (`triage_runs`), `save_checks`, `save_ticket`
  (stored when verdict and severity are in the enums, `valid` flag kept), `save_context_requests` (one row per
  `contexto` transcript entry, numbered in order, rows in `rows_json`). Each call commits.
- `workflow/pipeline.py::Triage(db_path, api=, llm_mode=, model=)`: `process(alert_id)` -> `Outcome(status=
  auto_closed|pending_llm|llm_done|llm_invalid|llm_error, verdict, severity, runs, detail)`. An `auto_check` run
  always; an `llm` run for kept alerts unless `llm_mode="none"`. Uses `ApiFacts` when the API object has
  `search_logs`. LLM exceptions are stored on the run (`status=error`, `errors_json`) and do not stop the queue.
  Stored transcripts drop `resultados` (already in `triage_context_requests.rows_json`); an unstorable ticket is
  appended to the transcript as `ticket_no_almacenable`.
- `python -m src.main [--llm anthropic|claude-code|mock|none] [--model M] [--limit N] [--db PATH] [--alert ID]`:
  ingest each new API alert, then `process` it; per-alert try/except; exit code 1 if any alert failed. `--alert`
  re-runs a stored alert (new runs are added; the UI shows the latest).
- Verified over HTTP with the dev mock API: 20 stored, 8 auto-closed, 12 mock LLM tickets (~16 s).
- Tests: `tests/test_workflow.py` (full feed, `--limit`, checks only, LLM failure and check failure isolation,
  error stored on the run, re-run).

### Step 7. Web app API (`src/webapp/`)

- `python -m src.webapp [--port 8080] [--db PATH]` -> http://127.0.0.1:8080 (redirects to `/ui/`, which serves
  `frontend/`). Localhost only, no authentication (local demo).
- `queries.py` (read side): `queue(conn, alert_id=None)` with derived status `new | pending_llm | in_llm |
  llm_error | auto_closed | awaiting_analyst | accepted | rejected` (a verdict decision only counts for the ticket
  run it reviewed); `detail()` (alert, entities, raw events via `log_record`, latest checks, latest LLM run with
  transcript and context requests, latest ticket, decisions, executed actions, alert_history); `decisions()`;
  `stats()`.
- `actions.py` (write side): `decide(conn, api, alert_id, Decision)`. Verdict accepted -> `alert_history` (upsert;
  `override_verdict` replaces the model's; `needs_more_info` requires an override); rejected -> decision only.
  Action accepted -> `api_action()` maps the text to a supported API action (escalate/review -> no execution);
  OT targets (`ot_reason`: LOGISTICS-OT host/IP or OT markers) are stored as `refused` without calling the API;
  `block_ioc`/`purge_email` run directly, others call `POST /approvals` (approver = analyst) then
  `POST /containment/{action}`; an item already executed `ok` returns 409. Everything in one transaction.
- `src/soc_api.py`: `post`, `approve`, `contain`, `SocApiError(status, detail)` (403 -> stored as `refused`).
- Endpoints: `GET /api/alerts`, `GET /api/alerts/{id}`, `GET /api/stats`, `GET /api/decisions`, `GET /api/config`,
  `POST /api/alerts/{id}/decisions` `{item: verdict|action:N, decision, analyst, run_id?, override_verdict?,
  comment?}`.
- Tests: `tests/test_webapp.py` (statuses, detail, alert_history only on accept, override, approval + single
  execution, block_ioc without approval, OT refusal, escalation recorded only, bad requests, stats, static UI,
  action mapping).

### Step 8. Frontend on real data (`frontend/app.js`)

- Rewritten from scratch on `/api/*` (the fake data and the duplicate `shell`/`approval` definitions are gone).
  All DOM is built with `el(tag, attrs, ...children)` and text nodes: no `innerHTML`, so alert fields, logs and
  model output (attacker-influenced) are always text.
- Operations center: analyst queue (filter by status, search, pagination, severity order), processing panel
  (stage line ingested -> checks -> LLM -> analyst, recently decided), indicators (`/api/stats`).
- Investigation drawer tabs: Alert (fields, untrusted description/evidence, entities, raw cited logs), Basic
  checks (outcome, guards, explanations, references), LLM transcript (run, type-2 requests with reason and queries,
  ticket attempts, rows returned), Ticket (verdict, evidence, actions with Approve & execute / Reject), Decisions
  (alert_history, decisions, executed actions, runs). Footer: accept/reject the verdict with optional override.
- "AI · basic checks" / "AI · LLM" vs "Human · <name>" badges everywhere; the analyst name is stored in
  `localStorage` (`tarvia.analyst`, default from `TARVIA_ANALYST`). Decision history page = `/api/decisions`.
- Auto-refresh every 10 s (paused while a textarea/select has focus).
- `index.html` unchanged (fonts, layout CSS); new classes appended to `styles.css`.
- Bug found in the browser and fixed: FastAPI runs the DB dependency and the endpoint on different threads ->
  `check_same_thread=False` on the per-request connection.
- Verified in the browser against the HTTP mock API: tabs, isolate with approval token (logged in
  `data/containment_log.jsonl`), second execution refused (409), verdict -> alert_history, escalation recorded only.

### Step 9. Demo run, docs, final checks

- `data/tarvia.sqlite` rebuilt context-only with the 62-table schema (`bash scripts/create_db.sh --context-only
  --replace`); it holds no alerts until `python -m src.main` runs.
- End to end over HTTP (dev mock API on :8000, `--llm mock`): 20 alerts stored, 8 auto-closed, 12 mock tickets;
  in the web UI: isolate with approval token -> `data/containment_log.jsonl`, repeat refused, verdict accepted ->
  `alert_history`, escalation recorded only.
- **Real LLM not exercised in this session:** `--llm claude-code` failed with "Credit balance is too low" (the
  local Claude Code CLI is logged in with an API account, not the plan). The failure was stored on the run
  (`llm_error`) and the queue continued, as designed. To fix: `claude` -> `/logout` -> `/login` with the plan
  account -> `/status`; or put `ANTHROPIC_API_KEY` in `.env` and use `--llm anthropic`.
- README (root, `src/llm_triage`, `src/prompt_builder`) updated; `httpx` added to `requirements-dev.txt`.
- `ruff check . && ruff format --check . && pytest`: green.

## How to continue

1. Run the real LLM on the debug feed and read the tickets in the UI (LLM transcript tab): check that the model
   follows the runbook, uses `solicitar_contexto` with sensible reasons and that severities respect the matrix.
   `python -m src.main --llm claude-code --alert <id>` re-runs one alert.
2. Known limits: G2 and the activity queries only see alerts/logs already ingested (no look-ahead, context-only
   DB); `api_action()` maps action text with keyword patterns (extend `ACTION_PATTERNS` if the model phrases actions
   differently); the web UI has no authentication (localhost only); `in_llm` is only visible while a run is in
   progress (the CLI and the UI are separate processes).
3. Full queue: `TARVIA_MOCK_ALERTS=all bash scripts/mock_api_dev.sh` then `python -m src.main --llm ... --limit N`.

### Follow-up: self-contained 20-alert test

- Test files: `dev/alertas_debug.jsonl` (20 alerts) and `dev/alertas_debug_events.jsonl` (45 raw log rows:
  cited events, parent emails of clicks, earlier same-device sign-ins); regenerate with
  `python scripts/make_debug_alerts.py`.
- `TARVIA_MOCK_LOGS=dev/alertas_debug_events.jsonl bash scripts/mock_api_dev.sh`: the dev mock API serves
  `/logs/{source}` only from that file (pre-filled cache; `docs/04_logs` never read). Same outcome as the full logs
  on this feed (8 auto-closed, 12 to the LLM); a full run with `--llm mock` takes ~1.3 s instead of ~16 s.
  Caveat: facts such as "the scanner IP never got a 2xx" are only checked against these rows.

### Follow-up: cluster model (`--llm openai`)

- `src/llm_triage/openai_compat.py`: `OpenAICompatibleLLM` posts to `{TARVIA_OPENAI_BASE_URL}/chat/completions` and
  translates the Anthropic message shape the loop already uses (tools, tool_use, tool_result). Anthropic and
  Claude Code are unchanged and do not read `TARVIA_OPENAI_*`.
- `.env` (never committed): `TARVIA_OPENAI_BASE_URL` (include `/v1`), `TARVIA_OPENAI_MODEL` (the id from
  `GET {base}/models`), optional `TARVIA_OPENAI_API_KEY` (Bearer), `TARVIA_OPENAI_TIMEOUT`, `TARVIA_OPENAI_MAX_TOKENS`.
- Run: `python -m src.main --llm openai --limit 5`. `--model` overrides `TARVIA_OPENAI_MODEL` for that process.
- The server must accept tool calls. A model that only returns free text is stored as `llm_invalid` after the loop
  asks once more for `emitir_ticket`.
