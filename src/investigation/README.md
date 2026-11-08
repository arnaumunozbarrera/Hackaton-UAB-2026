# investigation: reconstrucción de la cadena de ataque (N2)

Para lo que se escala: reconstruye la cadena de ataque, aunque dure días, con **origen**, **alcance** y **relación con
otros incidentes**. Parte de la descripción del triaje N1 (el ticket ya guardado) y el LLM lee la base de datos en
solo lectura hasta entregar un informe validado.

```
ticket N1 (escalado) ──► semilla desde la BD: alert_brief, alert_entities, alert_events, incident_links,
        │                entity_alerts de cada entidad en [alerta − 7 días, alerta + 3 días]
        ▼
ChainRunner ── LLM ──► solicitar_contexto(motivo, consultas[1..5])  (catálogo de investigación, máx. 10 peticiones)
        │          └─► emitir_informe(informe)                      (única salida válida)
        ▼
validate_report: esquema N2 + event_id, alert_id e incident_id existentes en la BD + timeline cronológica
        ▼                                     (si falla, el error vuelve al LLM; máx. 2 correcciones)
attack_chains (una fila por alerta) ──► GET /api/chain/{alert_id} ──► sección "Attack chain reconstruction" del front
```

## Qué entrega
`docs/01_contexto/informe_incidente.schema.json` ampliado con lo que muestra el front:

| Pregunta | Campos |
|---|---|
| Origen | `patient_zero`, `initial_access`, `root_cause` |
| Progresión (varios días) | `window {start, end}`, `timeline[]` con `timestamp`, `event_id`, `alert_id`, `phase` (táctica), `mitre`, `entity` |
| Alcance | `scope {users, hosts, data, business_impact}` |
| Relación con otros incidentes | `related_incidents[]` (incident_id o alert_id), `related_alerts[] {alert_id, relation}` |
| Resto | `attack_summary`, `containment_plan` (solo propuesta), `detection_gaps`, `open_questions`, `confidence` |

## Catálogo de lectura (`catalogue.py`)
Las consultas del triaje (menos `runbook_text` y `severity_matrix`) más consultas pensadas para varios días y varias
alertas: `entity_alerts`, `alert_brief`, `incident_members`, `user_daily`, `host_daily`, `ip_daily`, `ip_spread`,
`dst_hosts`, `hash_hosts`. Igual que en el triaje: nombre del catálogo, valores con `?`, 50 filas, conexión `mode=ro`.

## Cuándo se lanza
- Tras el triaje de una alerta (análisis desde el front o lote) cuyo ticket propone escalar.
- Cuando el operador pulsa **Escalate**.
- Al abrir en el front una alerta escalada sin reconstrucción, o con el botón **Reconstruct attack chain**.

Un único hilo procesa la cola (`service.py`): una reconstrucción a la vez y nunca dos para la misma alerta. Los disparos
automáticos no repiten una alerta que ya tiene informe; el botón sí lo regenera. El modo `--live` no la lanza por sí
mismo: se lanza al abrir la alerta escalada.

## Uso
```powershell
python -m src.llm_triage serve --claude-code          # el front la lanza; usa el mismo LLM que el análisis de detalle
python -m src.investigation ALR-20261010-011795 --claude-code
python -m src.investigation ALR-20261010-011795 --mock --no-save
```
API: `POST /api/chain {alert_id}` → `{job_id}`; `GET /api/chain-job?id=` (progreso); `GET /api/chain/{alert_id}`
(informe guardado y trabajo en curso).

## Tests
```powershell
python -m pytest tests/test_investigation.py -q
```
