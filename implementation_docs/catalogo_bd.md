# Tarvia SOC - Data catalog (single main database `tarvia_soc.sqlite`)

Hybrid SQLite: relations in columns + intact JSON records. 21 source tables (delivered data and documentation), a system layer with the values computed by L2/L3, a reference layer, and compatibility views so the existing scripts keep working.

| Layer | Tables |
|---|---|
| Source layer - inventory and business | usuario, activo, zona_red, tienda, servicio_negocio, activo_servicio, vulnerabilidad, evento_rrhh, cambio |
| Source layer - documentation | archivo_fuente, documento |
| Source layer - detection and relations | regla, alerta, alerta_evento, participacion |
| Source layer - events and intelligence | evento, ocurrencia_indicador, indicador, inteligencia, geoip, sandbox |
| System layer - computed results (preserved values) | resultado_alerta, fact_incident, bridge_alert_incident, fact_attack_step |
| Reference layer | dim_mitre, ref_severity_matrix |

Generated from the live database by `catalog.py`. PK = primary key, FK = foreign key.

## Source layer - inventory and business

### `usuario` - 1,224 rows

Directory identities (usuarios.csv). user_key = lower(username) is the join key used by the logs.

| Column | Type | Key | Description |
|---|---|---|---|
| user_id | TEXT | PK | user_key = lower(username): join key used by logs |
| user_key | TEXT |  |  |
| username | TEXT |  |  |
| upn | TEXT |  |  |
| display_name | TEXT |  |  |
| department | TEXT |  |  |
| title | TEXT |  |  |
| location | TEXT |  |  |
| manager_id | TEXT | FK -> usuario(user_id) |  |
| manager_upn | TEXT |  |  |
| account_type | TEXT |  |  |
| privileged | INTEGER |  |  |
| vip | INTEGER |  |  |
| mfa_method | TEXT |  |  |
| status | TEXT |  |  |
| created | TEXT |  |  |
| workstation_asset_id | TEXT | FK -> activo(asset_id) |  |
| workstation | TEXT |  |  |
| notes | TEXT |  |  |
| archivo_id | INTEGER | FK -> archivo_fuente(archivo_id) |  |
| linea | INTEGER |  |  |

### `activo` - 1,185 rows

CMDB assets (activos.csv) with resolved owner, zone, store and IP indicator.

| Column | Type | Key | Description |
|---|---|---|---|
| asset_id | TEXT | PK |  |
| hostname | TEXT |  |  |
| ip | TEXT |  |  |
| ip_indicador_id | INTEGER | FK -> indicador(indicador_id) |  |
| type | TEXT |  |  |
| os | TEXT |  |  |
| criticality | TEXT |  |  |
| criticality_level | INTEGER |  |  |
| zona | TEXT | FK -> zona_red(zona) |  |
| tienda | TEXT | FK -> tienda(tienda) |  |
| location | TEXT |  |  |
| business_service | TEXT |  |  |
| owner_user_id | TEXT | FK -> usuario(user_id) |  |
| owner_upn | TEXT |  |  |
| internet_facing | INTEGER |  |  |
| edr_installed | INTEGER |  |  |
| description | TEXT |  |  |
| archivo_id | INTEGER | FK -> archivo_fuente(archivo_id) |  |
| linea | INTEGER |  |  |

### `zona_red` - 10 rows

Network zones and CIDR ranges (zonas_red.csv).

| Column | Type | Key | Description |
|---|---|---|---|
| zona | TEXT | PK |  |
| cidr | TEXT |  |  |
| ubicacion | TEXT |  |  |
| descripcion | TEXT |  |  |

### `tienda` - 28 rows

Stores and their network (tiendas.csv).

| Column | Type | Key | Description |
|---|---|---|---|
| tienda | TEXT | PK |  |
| nombre | TEXT |  |  |
| ciudad | TEXT |  |  |
| red | TEXT |  |  |

### `servicio_negocio` - 14 rows

Business services, criticality, impact and owner (servicios_negocio.csv).

| Column | Type | Key | Description |
|---|---|---|---|
| servicio_id | INTEGER | PK |  |
| nombre | TEXT |  |  |
| criticidad | TEXT |  |  |
| impacto | TEXT |  |  |
| activos | TEXT |  |  |
| responsable | TEXT |  |  |

### `activo_servicio` - 1,151 rows

Asset-service links from both sources (activos.business_service and servicios_negocio.activos).

| Column | Type | Key | Description |
|---|---|---|---|
| asset_id | TEXT | PK FK -> activo(asset_id) |  |
| servicio_id | INTEGER | PK FK -> servicio_negocio(servicio_id) |  |
| metodo | TEXT |  | activos.business_service | servicios_negocio.activos | ambos |
| estado | TEXT |  | confirmado (two sources agree) | una_fuente |

### `vulnerabilidad` - 46 rows

Vulnerabilities per asset (vulnerabilidades.csv); cvss_valor = numeric part of severidad_cvss.

| Column | Type | Key | Description |
|---|---|---|---|
| vulnerabilidad_id | INTEGER | PK |  |
| asset_id | TEXT | FK -> activo(asset_id) |  |
| hostname | TEXT |  |  |
| cve | TEXT |  |  |
| producto | TEXT |  |  |
| severidad_cvss | TEXT |  |  |
| cvss_valor | REAL |  |  |
| estado | TEXT |  |  |
| detectada | TEXT |  |  |
| notas | TEXT |  |  |
| archivo_id | INTEGER | FK -> archivo_fuente(archivo_id) |  |
| linea | INTEGER |  |  |

### `evento_rrhh` - 17 rows

HR events: travel, leavers, joiners, role changes (eventos_rrhh.csv).

| Column | Type | Key | Description |
|---|---|---|---|
| rrhh_id | INTEGER | PK |  |
| user_id | TEXT | FK -> usuario(user_id) |  |
| usuario | TEXT |  |  |
| fecha | TEXT |  |  |
| tipo | TEXT |  |  |
| detalle | TEXT |  |  |
| fecha_efectiva | TEXT |  |  |
| archivo_id | INTEGER | FK -> archivo_fuente(archivo_id) |  |
| linea | INTEGER |  |  |

### `cambio` - 13 rows

Approved changes and authorised flows (calendario_cambios.csv). Times are local (Europe/Madrid). A match is evidence, not proof.

| Column | Type | Key | Description |
|---|---|---|---|
| cambio_id | TEXT | PK |  |
| titulo | TEXT |  |  |
| inicio | TEXT |  |  |
| fin | TEXT |  |  |
| solicitante | TEXT |  |  |
| condiciones | TEXT |  | column "detalle" of calendario_cambios.csv |
| alcance | TEXT |  | a time/scope match is evidence, not proof of authorisation |
| archivo_id | INTEGER | FK -> archivo_fuente(archivo_id) |  |
| linea | INTEGER |  |  |

## Source layer - documentation

### `archivo_fuente` - 69 rows

Every delivered file and project document, byte-identical (zlib) with SHA-256 and row count.

| Column | Type | Key | Description |
|---|---|---|---|
| archivo_id | INTEGER | PK |  |
| ruta | TEXT |  |  |
| rol | TEXT |  |  |
| formato | TEXT |  |  |
| bytes | INTEGER |  |  |
| sha256 | TEXT |  |  |
| filas | INTEGER |  |  |
| compresion | TEXT |  |  |
| original | BLOB |  |  |

### `documento` - 38 rows

Text of each document (README, policy, runbooks, schemas, tools, presentation, project docs).

| Column | Type | Key | Description |
|---|---|---|---|
| archivo_id | INTEGER | PK FK -> archivo_fuente(archivo_id) |  |
| codigo | TEXT |  |  |
| tipo | TEXT |  |  |
| titulo | TEXT |  |  |
| texto | TEXT |  |  |

## Source layer - detection and relations

### `regla` - 44 rows

Detection use cases (catalogo_casos_de_uso.csv); runbook -> documento.codigo.

| Column | Type | Key | Description |
|---|---|---|---|
| rule_id | TEXT | PK |  |
| nombre | TEXT |  |  |
| fuente | TEXT |  |  |
| severidad_base | TEXT |  |  |
| tactica | TEXT |  |  |
| tecnica_id | TEXT |  |  |
| tecnica | TEXT |  |  |
| runbook | TEXT | FK -> documento(codigo) |  |
| logica | TEXT |  |  |
| archivo_id | INTEGER | FK -> archivo_fuente(archivo_id) |  |
| linea | INTEGER |  |  |

### `alerta` - 11,061 rows

SIEM alerts with the complete original record in datos_json. Holds no system results.

| Column | Type | Key | Description |
|---|---|---|---|
| alert_id | TEXT | PK |  |
| fecha | TEXT |  |  |
| rule_id | TEXT | FK -> regla(rule_id) |  |
| estado | TEXT |  |  |
| source_product | TEXT |  |  |
| rule_name | TEXT |  |  |
| severidad | TEXT |  |  |
| descripcion | TEXT |  |  |
| tactica | TEXT |  |  |
| tecnica_id | TEXT |  |  |
| tecnica | TEXT |  |  |
| runbook | TEXT |  |  |
| archivo_id | INTEGER | FK -> archivo_fuente(archivo_id) |  |
| linea | INTEGER |  |  |
| datos_json | TEXT |  |  |

### `alerta_evento` - 15,683 rows

Ordered related_events of each alert (15,683 references, no loss).

| Column | Type | Key | Description |
|---|---|---|---|
| alert_id | TEXT | PK FK -> alerta(alert_id) |  |
| posicion | INTEGER | PK |  |
| event_id | TEXT | FK -> evento(event_id) |  |

### `participacion` - 1,445,057 rows

Entities (users, hosts, customers, cloud identities, sessions, processes) observed in an alert OR an event, with role, scope, JSON path and resolution.

| Column | Type | Key | Description |
|---|---|---|---|
| participacion_id | INTEGER | PK |  |
| alert_id | TEXT | FK -> alerta(alert_id) |  |
| event_id | TEXT | FK -> evento(event_id) |  |
| tipo | TEXT |  | user host customer process cloud_identity bucket access_key ai_session session file |
| rol | TEXT |  | ambito: interno externo cliente cloud desconocido |
| ambito | TEXT |  |  |
| valor_observado | TEXT |  |  |
| user_id | TEXT | FK -> usuario(user_id) |  |
| asset_id | TEXT | FK -> activo(asset_id) |  |
| ruta | TEXT |  | ruta = JSON path in the original record |
| metodo | TEXT |  |  |
| estado | TEXT |  |  |

## Source layer - events and intelligence

### `evento` - 814,471 rows

814,471 log events of the 18 sources; datos_json keeps every field. Shortcut columns for fast correlation.

| Column | Type | Key | Description |
|---|---|---|---|
| event_id | TEXT | PK | UTC |
| fuente | TEXT |  |  |
| timestamp | TEXT |  |  |
| accion | TEXT |  | value + field of origin |
| campo_accion | TEXT |  |  |
| resultado | TEXT |  |  |
| campo_resultado | TEXT |  |  |
| ip_origen | TEXT |  |  |
| ip_origen_indicador_id | INTEGER | FK -> indicador(indicador_id) |  |
| ip_destino | TEXT |  |  |
| ip_destino_indicador_id | INTEGER | FK -> indicador(indicador_id) |  |
| destino | TEXT |  | generic destination (domain, URL, app, bucket, ip:port) |
| user_key | TEXT |  | resolved shortcuts (full detail in participacion) |
| customer_id | TEXT |  |  |
| hostname | TEXT |  |  |
| sha256 | TEXT |  |  |
| ref_id | TEXT |  |  |
| archivo_id | INTEGER | FK -> archivo_fuente(archivo_id) |  |
| linea | INTEGER |  |  |
| datos_json | TEXT |  |  |

### `ocurrencia_indicador` - 2,041,758 rows

Where each indicator appears: alert, event or sandbox report (exactly one), with role and JSON path.

| Column | Type | Key | Description |
|---|---|---|---|
| ocurrencia_id | INTEGER | PK |  |
| indicador_id | INTEGER | FK -> indicador(indicador_id) |  |
| alert_id | TEXT | FK -> alerta(alert_id) |  |
| event_id | TEXT | FK -> evento(event_id) |  |
| sandbox_id | INTEGER | FK -> sandbox(indicador_id) |  |
| rol | TEXT |  |  |
| ruta | TEXT |  |  |

### `indicador` - 173,054 rows

Unique indicators (ip, domain, url, sha256, md5, email). UNIQUE(tipo, valor).

| Column | Type | Key | Description |
|---|---|---|---|
| indicador_id | INTEGER | PK |  |
| tipo | TEXT |  |  |
| valor | TEXT |  |  |
| normalizado | TEXT |  |  |

### `inteligencia` - 409 rows

Internal TIP (ti_feed.jsonl).

| Column | Type | Key | Description |
|---|---|---|---|
| indicador_id | INTEGER | PK FK -> indicador(indicador_id) |  |
| reputacion | TEXT |  |  |
| confianza | INTEGER |  |  |
| malware_family | TEXT |  |  |
| tags | TEXT |  |  |
| first_seen | TEXT |  |  |
| last_seen | TEXT |  |  |
| fuente | TEXT |  |  |
| nota | TEXT |  |  |
| archivo_id | INTEGER | FK -> archivo_fuente(archivo_id) |  |
| linea | INTEGER |  |  |

### `geoip` - 86,981 rows

GeoIP / ASN and anonymisation flags (geoip_asn.csv).

| Column | Type | Key | Description |
|---|---|---|---|
| indicador_id | INTEGER | PK FK -> indicador(indicador_id) |  |
| pais | TEXT |  |  |
| ciudad | TEXT |  |  |
| asn | TEXT |  |  |
| as_org | TEXT |  |  |
| is_tor | INTEGER |  |  |
| is_vpn_provider | INTEGER |  |  |
| is_hosting | INTEGER |  |  |
| is_residential_proxy | INTEGER |  |  |
| archivo_id | INTEGER | FK -> archivo_fuente(archivo_id) |  |
| linea | INTEGER |  |  |

### `sandbox` - 21 rows

Sandbox reports (sandbox_informes.jsonl); full report in datos_json.

| Column | Type | Key | Description |
|---|---|---|---|
| indicador_id | INTEGER | PK FK -> indicador(indicador_id) |  |
| md5 | TEXT |  |  |
| file_name | TEXT |  |  |
| veredicto | TEXT |  |  |
| score | INTEGER |  |  |
| malware_family | TEXT |  |  |
| analysis_env | TEXT |  |  |
| analyzed_at | TEXT |  |  |
| nota | TEXT |  |  |
| archivo_id | INTEGER | FK -> archivo_fuente(archivo_id) |  |
| linea | INTEGER |  |  |
| datos_json | TEXT |  |  |

## System layer - computed results (preserved values)

### `resultado_alerta` - 11,061 rows

System output per alert (L2): primary entities, dedup hash, verdict, final severity, rationale, authorisation.

| Column | Type | Key | Description |
|---|---|---|---|
| alert_id | TEXT | PK FK -> alerta(alert_id) |  |
| user_key | TEXT | FK -> usuario(user_key) |  |
| hostname | TEXT | FK -> activo(hostname) |  |
| context_key | TEXT |  | primary entities chosen by the system |
| event_id | TEXT | FK -> evento(event_id) |  |
| dedup_hash | TEXT |  |  |
| verdict | TEXT |  |  |
| final_severity | TEXT |  |  |
| severity_rationale | TEXT |  |  |
| confidence | REAL |  |  |
| action | TEXT |  |  |
| triaged_at | TEXT |  |  |
| authorised_by | TEXT |  |  |

### `fact_incident` - 861 rows

System output: incidents (L2 grouping) and investigation report fields (L3).

| Column | Type | Key | Description |
|---|---|---|---|
| incident_id | TEXT | PK |  |
| title | TEXT |  |  |
| first_seen | TEXT |  |  |
| last_seen | TEXT |  |  |
| alert_count | INTEGER |  |  |
| primary_user_key | TEXT | FK -> usuario(user_key) |  |
| primary_hostname | TEXT | FK -> activo(hostname) |  |
| tactics_covered | INTEGER |  |  |
| max_kill_chain_stage | INTEGER |  |  |
| verdict | TEXT |  |  |
| final_severity | TEXT |  |  |
| severity_rationale | TEXT |  |  |
| confidence | REAL |  |  |
| escalate_n2 | INTEGER |  |  |
| status | TEXT |  |  |
| related_incident_id | TEXT | FK -> fact_incident(incident_id) |  |
| patient_zero | TEXT |  |  |
| initial_access | TEXT | FK -> dim_mitre(technique_id) |  |
| scope | TEXT |  |  |
| root_cause | TEXT |  |  |
| containment_plan | TEXT |  |  |
| open_questions | TEXT |  |  |
| created_at | TEXT |  |  |
| updated_at | TEXT |  |  |
| escalation_reasons | TEXT |  |  |
| authorised_by | TEXT |  |  |
| triage_stage | TEXT |  |  |
| eradication_and_recovery | TEXT |  |  |
| notifications | TEXT |  |  |
| detection_gaps | TEXT |  |  |
| related_incidents | TEXT |  |  |

### `bridge_alert_incident` - 11,061 rows

System output: alert -> incident link with reason and score (L2).

| Column | Type | Key | Description |
|---|---|---|---|
| alert_id | TEXT | PK FK -> alerta(alert_id) |  |
| incident_id | TEXT | PK FK -> fact_incident(incident_id) |  |
| link_reason | TEXT |  |  |
| link_window | TEXT |  |  |
| link_score | REAL |  |  |
| is_duplicate | INTEGER |  |  |
| is_authorised | INTEGER |  |  |

### `fact_attack_step` - 153 rows

System output: reconstructed attack timeline (L3), evidence origin alert / hidden_log / context.

| Column | Type | Key | Description |
|---|---|---|---|
| step_id | INTEGER | PK |  |
| incident_id | TEXT | FK -> fact_incident(incident_id) |  |
| step_order | INTEGER |  |  |
| timestamp | TEXT |  |  |
| event_id | TEXT | FK -> evento(event_id) |  |
| alert_id | TEXT | FK -> alerta(alert_id) |  |
| technique_id | TEXT | FK -> dim_mitre(technique_id) |  |
| user_key | TEXT |  |  |
| hostname | TEXT |  |  |
| context_key | TEXT |  |  |
| evidence_origin | TEXT |  |  |
| description | TEXT |  |  |
| confidence | REAL |  |  |

## Reference layer

### `dim_mitre` - 710 rows

MITRE ATT&CK Enterprise (+ ICS / ATLAS ids used by the dataset): tactic, kill-chain order, data sources, mitigations.

| Column | Type | Key | Description |
|---|---|---|---|
| technique_id | TEXT | PK | T1566.002 |
| technique | TEXT |  |  |
| is_subtechnique | INTEGER |  |  |
| parent_technique_id | TEXT |  |  |
| tactic | TEXT |  | primary tactic (earliest kill-chain stage) |
| tactic_id | TEXT |  | TA0001 |
| tactics_all | TEXT |  | all tactics, comma-separated |
| kill_chain_order | INTEGER |  | 1 (Reconnaissance) .. 14 (Impact) |
| data_sources | TEXT |  | which telemetry detects it |
| mitigations | TEXT |  | Mxxxx: name ; ... |
| url | TEXT |  |  |
| in_dataset | INTEGER |  | referenced by alerts / rules / sandbox |
| framework | TEXT |  | enterprise / ics / atlas |
| revoked_by | TEXT |  | successor id when revoked in ATT&CK |

### `ref_severity_matrix` - 20 rows

Severity matrix of politica_soc.md section 2.

| Column | Type | Key | Description |
|---|---|---|---|
| rule_severity | TEXT | PK |  |
| criticality | TEXT | PK |  |
| base_severity | TEXT |  |  |

## Views

| View | Purpose |
|---|---|
| `fact_alert` | Compatibility: alerta + resultado_alerta with the previous column names (INSTEAD OF UPDATE trigger writes to resultado_alerta). |
| `dim_log` | Compatibility: evento with the previous column names. |
| `dim_user` | Compatibility: usuario + latest evento_rrhh. |
| `dim_vulnerability` | Compatibility: activo + service + aggregated vulnerabilities. |
| `dim_context` | Compatibility: indicators with TIP / GeoIP / sandbox data + approved changes. |
| `dim_rule` | Compatibility: regla + runbook sections (Comprobaciones / Decisión) from documento. |
| `bridge_alert_entity` | Compatibility: alert entities (participacion + ocurrencia_indicador), original JSON order. |
| `bridge_alert_event` | Compatibility: alerta_evento. |
| `v_alert_enriched` | Alert with every dimension and the matrix base severity. |
| `v_alert_change_overlap` | Approved changes active at alert time (+ entity_match, window_hours). |
| `v_alert_duplicates` | Groups of identical alerts (rule + entities + day). |
| `v_incident_queue` | Analyst queue ordered by status, severity, SLA. |
| `v_incident_timeline` | L3 timeline with MITRE tactic and kill-chain order. |
