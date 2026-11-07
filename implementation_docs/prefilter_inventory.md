# Pre-filter inventory and iteration log

Inventory performed 2026-11-07 from `db/l2_correlate.py`, `db/build_db.py`, the Tarvia policy, company rules, and database views:

| Definition | Category | Target | Implementation |
|---|---|---|---|
| `intelligence.reputation=malicious` / `sandbox_verdict=malicious` | known_malicious_hash (or indicator type) | input_alert, similar_alert, log | `PF-MAL-IOC`, `PF-KNOWN-IOC-LOG` |
| `v_alert_change_overlap` plus structured entity match | approved_change, authorised_activity | input_alert, similar_alert | `PF-APPROVED-CHANGE` |
| `v_alert_duplicates` / duplicate correlation | duplicate | similar_alert | `PF-DUPLICATE` |
| `EFFECT_RULES`, `PII_PAYMENT_RULES`, `FRAUD_RULES`, `CRED_THEFT_RULES` | policy scoring, not withholding | alert | reused as policy context only |
| Admin/JUMP01, NESSUS schedule, payroll flow, Logisoft/WMS01, OT allow-list | authorised_activity / approved_change candidates | alert/log | policy candidates; no literal list copied |

No standalone repository-owned IP/domain/URL/hash allow/deny list was found. NULL reputation is unknown and never matches.

## Iteration log

1. Registry exploration is read-only; match counts are recorded by `meta.prefilter.withheld_counts` in each package. Enabled withholding is limited to malicious intelligence, entity-matched approved changes, and duplicates.
2. Safety review retains high/critical rules, `Alta`/`Crítica` assets, and privileged/VIP users with `guard_applied`.
3. Matcher exceptions fail open and are appended to `meta.prefilter.errors`.
4. Proposed but disabled: `is_authorised=1`/`authorised_by`, benign history by rule/entity, `dim_context.tags`/`ti_source` labels, and scheduled-agent patterns. Each needs a stable taxonomy or explicit policy before withholding.

The database is never used to store filter results.
