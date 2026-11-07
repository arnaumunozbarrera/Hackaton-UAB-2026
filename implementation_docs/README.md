# Tarvia SOC - database

Single main database: `tarvia_soc.sqlite` (hybrid SQLite: relations in columns + intact JSON records).

## Layers
| Layer | Tables | Written by |
|---|---|---|
| Source (21 tables) | usuario, activo, zona_red, tienda, servicio_negocio, activo_servicio, vulnerabilidad, evento_rrhh, cambio, archivo_fuente, documento, regla, alerta, alerta_evento, participacion, evento, ocurrencia_indicador, indicador, inteligencia, geoip, sandbox | `build_db.py` + `migrate_hybrid.py` |
| System results | resultado_alerta, fact_incident, bridge_alert_incident, fact_attack_step | `l2_correlate.py`, `l3_reconstruct.py` |
| Reference | dim_mitre, ref_severity_matrix | `build_db.py` |
| Compatibility views | fact_alert, dim_log, dim_user, dim_vulnerability, dim_context, dim_rule, bridge_alert_entity, bridge_alert_event | `migrate_hybrid.py` |
| Analytical views | v_alert_enriched, v_alert_change_overlap, v_alert_duplicates, v_incident_queue, v_incident_timeline | `build_db.py`, `l2_correlate.py` |

Rules: source tables are never modified by the system; `alerta` holds no results (they live in `resultado_alerta`);
every source record keeps its complete JSON and its file + line (`archivo_id`, `linea`); every delivered file is stored
byte-identical in `archivo_fuente.original` (zlib) with its SHA-256.

## Rebuild from scratch
```bash
python build_db.py --data ../docs --out tarvia_soc.sqlite --mitre enterprise-attack.json   # loads data + converts to the hybrid schema
python l2_correlate.py --db tarvia_soc.sqlite                                              # grouping, severity, authorised activity
python l3_reconstruct.py --db tarvia_soc.sqlite --reports reports                          # attack-chain reconstruction
python catalog.py --db tarvia_soc.sqlite                                                   # catalogo_bd.md + schema.sql
```
A new L2 run regenerates all incidents (re-run L3 afterwards) and refuses to discard analyst work unless `--force`.
L2 and L3 are deterministic: two runs on the same data produce identical results.

## Files
`build_db.py` loader · `migrate_hybrid.py` hybrid schema · `l2_correlate.py` L2 · `l3_reconstruct.py` L3 · `catalog.py` docs ·
`catalogo_bd.md` data dictionary · `schema.sql` DDL · `reports/` L3 incident reports · `enterprise-attack.json` MITRE ATT&CK (offline).
