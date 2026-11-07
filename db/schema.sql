CREATE TABLE activo (
  asset_id TEXT PRIMARY KEY, hostname TEXT UNIQUE NOT NULL, ip TEXT, ip_indicador_id INTEGER REFERENCES indicador(indicador_id),
  type TEXT, os TEXT, criticality TEXT, criticality_level INTEGER, zona TEXT REFERENCES zona_red(zona),
  tienda TEXT REFERENCES tienda(tienda), location TEXT, business_service TEXT,
  owner_user_id TEXT REFERENCES usuario(user_id), owner_upn TEXT, internet_facing INTEGER, edr_installed INTEGER, description TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);

CREATE TABLE activo_servicio (
  asset_id TEXT NOT NULL REFERENCES activo(asset_id), servicio_id INTEGER NOT NULL REFERENCES servicio_negocio(servicio_id),
  metodo TEXT,      -- activos.business_service | servicios_negocio.activos | ambos
  estado TEXT,      -- confirmado (two sources agree) | una_fuente
  PRIMARY KEY (asset_id, servicio_id));

CREATE TABLE alerta (
  alert_id TEXT PRIMARY KEY, fecha TEXT NOT NULL, rule_id TEXT REFERENCES regla(rule_id), estado TEXT,
  source_product TEXT, rule_name TEXT, severidad TEXT, descripcion TEXT, tactica TEXT, tecnica_id TEXT, tecnica TEXT,
  runbook TEXT, archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER,
  datos_json TEXT NOT NULL);

CREATE TABLE alerta_evento (
  alert_id TEXT NOT NULL REFERENCES alerta(alert_id), posicion INTEGER NOT NULL,
  event_id TEXT NOT NULL REFERENCES evento(event_id), PRIMARY KEY (alert_id, posicion));

CREATE TABLE archivo_fuente (
  archivo_id INTEGER PRIMARY KEY, ruta TEXT UNIQUE NOT NULL, rol TEXT, formato TEXT, bytes INTEGER, sha256 TEXT,
  filas INTEGER, compresion TEXT, original BLOB NOT NULL);

CREATE TABLE bridge_alert_incident (
      alert_id TEXT NOT NULL REFERENCES alerta(alert_id), incident_id TEXT NOT NULL REFERENCES fact_incident(incident_id),
      link_reason TEXT, link_window TEXT, link_score REAL, is_duplicate INTEGER DEFAULT 0, is_authorised INTEGER DEFAULT 0,
      PRIMARY KEY (alert_id, incident_id));

CREATE TABLE cambio (
  cambio_id TEXT PRIMARY KEY, titulo TEXT, inicio TEXT, fin TEXT, solicitante TEXT,
  condiciones TEXT,  -- column "detalle" of calendario_cambios.csv
  alcance TEXT,      -- a time/scope match is evidence, not proof of authorisation
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);

CREATE TABLE dim_mitre (
  technique_id        TEXT PRIMARY KEY,          -- T1566.002
  technique           TEXT NOT NULL,
  is_subtechnique     INTEGER NOT NULL DEFAULT 0,
  parent_technique_id TEXT,
  tactic              TEXT,                      -- primary tactic (earliest kill-chain stage)
  tactic_id           TEXT,                      -- TA0001
  tactics_all         TEXT,                      -- all tactics, comma-separated
  kill_chain_order    INTEGER,                   -- 1 (Reconnaissance) .. 14 (Impact)
  data_sources        TEXT,                      -- which telemetry detects it
  mitigations         TEXT,                      -- Mxxxx: name ; ...
  url                 TEXT,
  in_dataset          INTEGER NOT NULL DEFAULT 0, -- referenced by alerts / rules / sandbox
  framework           TEXT,                       -- enterprise / ics / atlas
  revoked_by          TEXT                        -- successor id when revoked in ATT&CK
);

CREATE TABLE documento (
  archivo_id INTEGER PRIMARY KEY REFERENCES archivo_fuente(archivo_id), codigo TEXT UNIQUE NOT NULL, tipo TEXT,
  titulo TEXT, texto TEXT);

CREATE TABLE evento (
  event_id TEXT PRIMARY KEY, fuente TEXT NOT NULL, timestamp TEXT NOT NULL,       -- UTC
  accion TEXT, campo_accion TEXT, resultado TEXT, campo_resultado TEXT,            -- value + field of origin
  ip_origen TEXT, ip_origen_indicador_id INTEGER REFERENCES indicador(indicador_id),
  ip_destino TEXT, ip_destino_indicador_id INTEGER REFERENCES indicador(indicador_id),
  destino TEXT,                  -- generic destination (domain, URL, app, bucket, ip:port)
  user_key TEXT, customer_id TEXT, hostname TEXT, sha256 TEXT, ref_id TEXT,          -- resolved shortcuts (full detail in participacion)
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER,
  datos_json TEXT NOT NULL);

CREATE TABLE common_log_pattern (
  pattern_id TEXT PRIMARY KEY,
  pattern_name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL,
  source_product TEXT,
  action TEXT,
  result TEXT,
  normalized_fingerprint TEXT,
  message_template TEXT,
  classification TEXT NOT NULL CHECK (classification IN ('noise', 'benign_expected', 'common_cross_product', 'candidate')),
  filtering_action TEXT NOT NULL DEFAULT 'retain' CHECK (filtering_action IN ('retain', 'aggregate', 'hide_from_triage')),
  confidence REAL CHECK (confidence BETWEEN 0 AND 1),
  rationale TEXT,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);

CREATE TABLE log_pattern_match (
  event_id TEXT NOT NULL REFERENCES evento(event_id),
  pattern_id TEXT NOT NULL REFERENCES common_log_pattern(pattern_id),
  matched_by TEXT NOT NULL,
  match_confidence REAL CHECK (match_confidence BETWEEN 0 AND 1),
  matched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (event_id, pattern_id));

CREATE TABLE evento_rrhh (
  rrhh_id INTEGER PRIMARY KEY, user_id TEXT REFERENCES usuario(user_id), usuario TEXT,
  fecha TEXT, tipo TEXT, detalle TEXT, fecha_efectiva TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);

CREATE TABLE fact_attack_step (
      step_id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL REFERENCES fact_incident(incident_id),
      step_order INTEGER NOT NULL, timestamp TEXT NOT NULL, event_id TEXT REFERENCES evento(event_id),
      alert_id TEXT REFERENCES alerta(alert_id), technique_id TEXT REFERENCES dim_mitre(technique_id),
      user_key TEXT, hostname TEXT, context_key TEXT,
      evidence_origin TEXT CHECK (evidence_origin IN ('alert','hidden_log','context')), description TEXT, confidence REAL);

CREATE TABLE fact_incident (
      incident_id TEXT PRIMARY KEY, title TEXT, first_seen TEXT, last_seen TEXT, alert_count INTEGER,
      primary_user_key TEXT REFERENCES usuario(user_key), primary_hostname TEXT REFERENCES activo(hostname),
      tactics_covered INTEGER, max_kill_chain_stage INTEGER, verdict TEXT, final_severity TEXT, severity_rationale TEXT,
      confidence REAL, escalate_n2 INTEGER, status TEXT, related_incident_id TEXT REFERENCES fact_incident(incident_id),
      patient_zero TEXT, initial_access TEXT REFERENCES dim_mitre(technique_id), scope TEXT, root_cause TEXT, containment_plan TEXT,
      open_questions TEXT, created_at TEXT, updated_at TEXT, escalation_reasons TEXT, authorised_by TEXT, triage_stage TEXT,
      eradication_and_recovery TEXT, notifications TEXT, detection_gaps TEXT, related_incidents TEXT);

CREATE TABLE geoip (
  indicador_id INTEGER PRIMARY KEY REFERENCES indicador(indicador_id), pais TEXT, ciudad TEXT, asn TEXT, as_org TEXT,
  is_tor INTEGER, is_vpn_provider INTEGER, is_hosting INTEGER, is_residential_proxy INTEGER,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);

CREATE TABLE indicador (
  indicador_id INTEGER PRIMARY KEY, tipo TEXT NOT NULL, valor TEXT NOT NULL, normalizado TEXT,
  UNIQUE (tipo, valor));

CREATE TABLE inteligencia (
  indicador_id INTEGER PRIMARY KEY REFERENCES indicador(indicador_id), reputacion TEXT, confianza INTEGER,
  malware_family TEXT, tags TEXT, first_seen TEXT, last_seen TEXT, fuente TEXT, nota TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);

CREATE TABLE ocurrencia_indicador (
  ocurrencia_id INTEGER PRIMARY KEY, indicador_id INTEGER NOT NULL REFERENCES indicador(indicador_id),
  alert_id TEXT REFERENCES alerta(alert_id), event_id TEXT REFERENCES evento(event_id),
  sandbox_id INTEGER REFERENCES sandbox(indicador_id),
  rol TEXT, ruta TEXT,
  CHECK ((alert_id IS NOT NULL) + (event_id IS NOT NULL) + (sandbox_id IS NOT NULL) = 1));

CREATE TABLE participacion (
  participacion_id INTEGER PRIMARY KEY,
  alert_id TEXT REFERENCES alerta(alert_id), event_id TEXT REFERENCES evento(event_id),
  tipo TEXT NOT NULL,            -- user host customer process cloud_identity bucket access_key ai_session session file
  rol TEXT, ambito TEXT,         -- ambito: interno externo cliente cloud desconocido
  valor_observado TEXT NOT NULL,
  user_id TEXT REFERENCES usuario(user_id), asset_id TEXT REFERENCES activo(asset_id),
  ruta TEXT, metodo TEXT, estado TEXT,       -- ruta = JSON path in the original record
  CHECK ((alert_id IS NULL) <> (event_id IS NULL)));

CREATE TABLE ref_severity_matrix (               -- politica_soc.md section 2
  rule_severity TEXT NOT NULL,
  criticality   TEXT NOT NULL,
  base_severity TEXT NOT NULL,
  PRIMARY KEY (rule_severity, criticality)
);

CREATE TABLE regla (
  rule_id TEXT PRIMARY KEY, nombre TEXT, fuente TEXT, severidad_base TEXT, tactica TEXT, tecnica_id TEXT, tecnica TEXT,
  runbook TEXT REFERENCES documento(codigo), logica TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);

CREATE TABLE resultado_alerta (
  alert_id TEXT PRIMARY KEY REFERENCES alerta(alert_id),
  user_key TEXT REFERENCES usuario(user_key), hostname TEXT REFERENCES activo(hostname),
  context_key TEXT, event_id TEXT REFERENCES evento(event_id),   -- primary entities chosen by the system
  dedup_hash TEXT, verdict TEXT, final_severity TEXT, severity_rationale TEXT, confidence REAL, action TEXT,
  triaged_at TEXT, authorised_by TEXT);

CREATE TABLE sandbox (
  indicador_id INTEGER PRIMARY KEY REFERENCES indicador(indicador_id), md5 TEXT, file_name TEXT, veredicto TEXT, score INTEGER,
  malware_family TEXT, analysis_env TEXT, analyzed_at TEXT, nota TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER,
  datos_json TEXT NOT NULL);

CREATE TABLE servicio_negocio (servicio_id INTEGER PRIMARY KEY, nombre TEXT UNIQUE NOT NULL, criticidad TEXT,
  impacto TEXT, activos TEXT, responsable TEXT);

CREATE TABLE tienda (tienda TEXT PRIMARY KEY, nombre TEXT, ciudad TEXT, red TEXT);

CREATE TABLE usuario (
  user_id TEXT PRIMARY KEY, user_key TEXT UNIQUE NOT NULL,          -- user_key = lower(username): join key used by logs
  username TEXT, upn TEXT UNIQUE, display_name TEXT, department TEXT, title TEXT, location TEXT,
  manager_id TEXT REFERENCES usuario(user_id), manager_upn TEXT,
  account_type TEXT, privileged INTEGER, vip INTEGER, mfa_method TEXT, status TEXT, created TEXT,
  workstation_asset_id TEXT REFERENCES activo(asset_id), workstation TEXT, notes TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);

CREATE TABLE vulnerabilidad (
  vulnerabilidad_id INTEGER PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES activo(asset_id), hostname TEXT,
  cve TEXT, producto TEXT, severidad_cvss TEXT, cvss_valor REAL, estado TEXT, detectada TEXT, notas TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);

CREATE TABLE zona_red (zona TEXT PRIMARY KEY, cidr TEXT, ubicacion TEXT, descripcion TEXT);

CREATE INDEX ix_ae_event         ON alerta_evento(event_id);

CREATE INDEX ix_alerta_fecha     ON alerta(fecha);

CREATE INDEX ix_alerta_rule      ON alerta(rule_id);

CREATE INDEX ix_bai_incident ON bridge_alert_incident(incident_id);

CREATE INDEX ix_evento_cust_ts   ON evento(customer_id, timestamp);

CREATE INDEX ix_evento_dst       ON evento(destino);

CREATE INDEX ix_evento_fuente_ts ON evento(fuente, timestamp);
CREATE INDEX ix_common_pattern_fingerprint ON common_log_pattern(normalized_fingerprint);
CREATE INDEX ix_common_pattern_source_action ON common_log_pattern(source_product, action, result);
CREATE INDEX ix_log_pattern_match_pattern ON log_pattern_match(pattern_id);
CREATE INDEX ix_log_pattern_match_event ON log_pattern_match(event_id);

CREATE INDEX ix_evento_host_ts   ON evento(hostname, timestamp);

CREATE INDEX ix_evento_ref       ON evento(ref_id);

CREATE INDEX ix_evento_sha       ON evento(sha256);

CREATE INDEX ix_evento_src_ts    ON evento(ip_origen, timestamp);

CREATE INDEX ix_evento_user_ts   ON evento(user_key, timestamp);

CREATE INDEX ix_ind_norm         ON indicador(normalizado);

CREATE INDEX ix_occ_alert        ON ocurrencia_indicador(alert_id);

CREATE INDEX ix_occ_event        ON ocurrencia_indicador(event_id);

CREATE INDEX ix_occ_ind          ON ocurrencia_indicador(indicador_id);

CREATE INDEX ix_part_alert       ON participacion(alert_id);

CREATE INDEX ix_part_asset       ON participacion(asset_id);

CREATE INDEX ix_part_event       ON participacion(event_id);

CREATE INDEX ix_part_user        ON participacion(user_id);

CREATE INDEX ix_part_valor       ON participacion(tipo, valor_observado);

CREATE INDEX ix_res_dedup        ON resultado_alerta(dedup_hash);

CREATE INDEX ix_res_host         ON resultado_alerta(hostname);

CREATE INDEX ix_res_user         ON resultado_alerta(user_key);

CREATE INDEX ix_rrhh_user        ON evento_rrhh(user_id);

CREATE INDEX ix_step_incident ON fact_attack_step(incident_id, step_order);

CREATE INDEX ix_vuln_asset       ON vulnerabilidad(asset_id);

CREATE VIEW bridge_alert_entity AS
  SELECT alert_id, entity_type, entity_value, user_key, hostname, context_key, orden FROM (
  SELECT p.alert_id, p.tipo AS entity_type, p.valor_observado AS entity_value, u.user_key, a.hostname, NULL AS context_key,
         (CASE WHEN p.ruta LIKE 'entities.users%' THEN 1 WHEN p.ruta LIKE 'entities.hosts%' THEN 2 WHEN p.ruta LIKE 'entities.ips%' THEN 3
            WHEN p.ruta LIKE 'entities.domains%' THEN 4 WHEN p.ruta LIKE 'entities.urls%' THEN 5 WHEN p.ruta LIKE 'entities.files%' THEN 6
            WHEN p.ruta LIKE 'entities.customers%' THEN 7 WHEN p.ruta LIKE 'entities.processes%' THEN 8
            WHEN p.ruta = 'entities.cloud.identity' THEN 9 WHEN p.ruta = 'entities.cloud.new_user' THEN 10 WHEN p.ruta = 'entities.cloud.bucket' THEN 11
            WHEN p.ruta = 'entities.cloud.access_key' THEN 12 ELSE 13 END) * 100000
         + COALESCE(CAST(substr(p.ruta, instr(p.ruta, '[') + 1, instr(p.ruta, ']') - instr(p.ruta, '[') - 1) AS INTEGER), 0) * 10
         + (CASE WHEN p.ruta LIKE '%.ip' THEN 1 ELSE 0 END) AS orden
  FROM participacion p LEFT JOIN usuario u ON u.user_id = p.user_id AND p.tipo = 'user' LEFT JOIN activo a ON a.asset_id = p.asset_id
  WHERE p.alert_id IS NOT NULL
  UNION ALL
  SELECT o.alert_id, CASE i.tipo WHEN 'sha256' THEN 'file' ELSE i.tipo END, i.valor, NULL, NULL,
         CASE WHEN EXISTS (SELECT 1 FROM inteligencia t WHERE t.indicador_id = i.indicador_id)
                OR EXISTS (SELECT 1 FROM geoip g WHERE g.indicador_id = i.indicador_id)
                OR EXISTS (SELECT 1 FROM sandbox s WHERE s.indicador_id = i.indicador_id) THEN i.valor END,
         (CASE WHEN o.ruta LIKE 'entities.users%' THEN 1 WHEN o.ruta LIKE 'entities.hosts%' THEN 2 WHEN o.ruta LIKE 'entities.ips%' THEN 3
            WHEN o.ruta LIKE 'entities.domains%' THEN 4 WHEN o.ruta LIKE 'entities.urls%' THEN 5 WHEN o.ruta LIKE 'entities.files%' THEN 6
            WHEN o.ruta LIKE 'entities.customers%' THEN 7 WHEN o.ruta LIKE 'entities.processes%' THEN 8
            WHEN o.ruta = 'entities.cloud.identity' THEN 9 WHEN o.ruta = 'entities.cloud.new_user' THEN 10 WHEN o.ruta = 'entities.cloud.bucket' THEN 11
            WHEN o.ruta = 'entities.cloud.access_key' THEN 12 ELSE 13 END) * 100000
         + COALESCE(CAST(substr(o.ruta, instr(o.ruta, '[') + 1, instr(o.ruta, ']') - instr(o.ruta, '[') - 1) AS INTEGER), 0) * 10
         + (CASE WHEN o.ruta LIKE '%.ip' THEN 1 ELSE 0 END)
  FROM ocurrencia_indicador o JOIN indicador i USING(indicador_id) WHERE o.alert_id IS NOT NULL)
  ORDER BY alert_id, orden;

CREATE VIEW bridge_alert_event AS
  SELECT ae.alert_id, ae.event_id, 1 AS in_dim_log FROM alerta_evento ae;

CREATE VIEW v_common_log_matches AS
  SELECT e.event_id, e.fuente AS source_product, e.timestamp, e.accion AS action, e.resultado AS result,
         p.pattern_id, p.pattern_name, p.classification, p.filtering_action,
         m.matched_by, m.match_confidence
  FROM evento e
  JOIN log_pattern_match m ON m.event_id = e.event_id
  JOIN common_log_pattern p ON p.pattern_id = m.pattern_id;

CREATE VIEW v_useful_logs AS
  SELECT e.*
  FROM evento e
  WHERE NOT EXISTS (
    SELECT 1
    FROM log_pattern_match m
    JOIN common_log_pattern p ON p.pattern_id = m.pattern_id
    WHERE m.event_id = e.event_id AND p.enabled = 1 AND p.filtering_action = 'hide_from_triage'
  );

CREATE VIEW v_common_log_candidates AS
  SELECT accion AS action, resultado AS result, COUNT(*) AS event_count,
         COUNT(DISTINCT fuente) AS product_count, COUNT(DISTINCT event_id) AS distinct_event_count
  FROM evento
  GROUP BY accion, resultado
  HAVING COUNT(DISTINCT fuente) > 1;

CREATE VIEW dim_context AS
  SELECT i.valor AS context_key, i.tipo AS context_type, t.reputacion AS reputation, t.confianza AS confidence,
         t.malware_family, t.tags, t.first_seen, t.last_seen, t.fuente AS ti_source, t.nota AS ti_note,
         g.pais AS country, g.ciudad AS city, g.asn, g.as_org, g.is_tor, g.is_vpn_provider, g.is_hosting, g.is_residential_proxy,
         s.file_name AS sandbox_file_name, s.veredicto AS sandbox_verdict, s.score AS sandbox_score, s.malware_family AS sandbox_family,
         (SELECT GROUP_CONCAT(value, ',') FROM json_each(s.datos_json, '$.mitre')) AS sandbox_mitre,
         json_extract(s.datos_json, '$.behaviors') AS sandbox_behaviors, json_extract(s.datos_json, '$.network') AS sandbox_network,
         NULL AS change_title, NULL AS change_start, NULL AS change_end, NULL AS change_requester, NULL AS change_detail, NULL AS change_scope
  FROM indicador i LEFT JOIN inteligencia t USING(indicador_id) LEFT JOIN geoip g USING(indicador_id) LEFT JOIN sandbox s USING(indicador_id)
  WHERE t.indicador_id IS NOT NULL OR g.indicador_id IS NOT NULL OR s.indicador_id IS NOT NULL
  UNION ALL
  SELECT cambio_id, 'change', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         NULL, NULL, NULL, NULL, NULL, NULL, NULL, titulo, inicio, fin, solicitante, condiciones, alcance FROM cambio;

CREATE VIEW dim_log AS
  SELECT event_id, fuente AS source, timestamp, user_key, customer_id, hostname, ip_origen AS src_ip, destino AS dst,
         accion AS action, resultado AS result, sha256, ref_id, datos_json AS detail FROM evento;

CREATE VIEW dim_rule AS
  SELECT r.rule_id, r.nombre, r.fuente, r.severidad_base, r.tactica, r.tecnica_id, r.tecnica, r.runbook, r.logica,
         trim(substr(d.texto, instr(d.texto, '## Comprobaciones') + 18,
                     CASE WHEN instr(d.texto, '## Decisi') > 0 THEN instr(d.texto, '## Decisi') - instr(d.texto, '## Comprobaciones') - 18 ELSE 100000 END)) AS runbook_checks,
         CASE WHEN instr(d.texto, '## Decisi') > 0 THEN trim(substr(d.texto, instr(d.texto, '## Decisi') + 12)) END AS runbook_decision
  FROM regla r LEFT JOIN documento d ON d.codigo = r.runbook;

CREATE VIEW dim_user AS
  SELECT u.user_key, u.user_id, u.username, u.upn, u.display_name, u.department, u.title, u.location, u.manager_upn,
         u.account_type, u.privileged, u.vip, u.mfa_method, u.status, u.workstation, u.notes,
         h.tipo AS hr_event, h.fecha AS hr_event_date, h.fecha_efectiva AS hr_fecha_efectiva, h.detalle AS hr_detalle
  FROM usuario u LEFT JOIN evento_rrhh h ON h.rrhh_id = (SELECT rrhh_id FROM evento_rrhh x WHERE x.user_id = u.user_id ORDER BY fecha DESC LIMIT 1);

CREATE VIEW dim_vulnerability AS
  SELECT a.hostname, a.asset_id, a.ip, a.type, a.os, a.criticality, a.criticality_level, a.zona AS zone, a.location,
         a.business_service,
         (SELECT s.criticidad FROM activo_servicio x JOIN servicio_negocio s USING(servicio_id) WHERE x.asset_id=a.asset_id
          ORDER BY CASE s.criticidad WHEN 'Crítica' THEN 0 WHEN 'Alta' THEN 1 WHEN 'Media' THEN 2 ELSE 3 END LIMIT 1) AS service_criticidad,
         (SELECT s.responsable FROM activo_servicio x JOIN servicio_negocio s USING(servicio_id) WHERE x.asset_id=a.asset_id
          ORDER BY CASE s.criticidad WHEN 'Crítica' THEN 0 WHEN 'Alta' THEN 1 WHEN 'Media' THEN 2 ELSE 3 END LIMIT 1) AS service_responsable,
         a.owner_upn, a.internet_facing, a.edr_installed, a.description,
         (SELECT COUNT(*) FROM vulnerabilidad v WHERE v.asset_id=a.asset_id AND v.estado='abierta') AS open_vuln_count,
         (SELECT MAX(cvss_valor) FROM vulnerabilidad v WHERE v.asset_id=a.asset_id AND v.estado='abierta') AS max_cvss_open,
         (SELECT GROUP_CONCAT(v.cve||':'||v.producto||':'||v.severidad_cvss||':'||v.estado, ' ; ') FROM vulnerabilidad v WHERE v.asset_id=a.asset_id) AS cve_ids,
         (SELECT GROUP_CONCAT(v.notas, ' ; ') FROM vulnerabilidad v WHERE v.asset_id=a.asset_id) AS vuln_notes
  FROM activo a;

CREATE VIEW fact_alert AS
  SELECT a.alert_id, a.fecha AS created_at, a.rule_id, a.tecnica_id AS technique_id, r.user_key, r.hostname, r.context_key, r.event_id,
         a.source_product, a.rule_name, a.severidad AS rule_severity, a.estado AS status, a.tactica AS mitre_tactic, a.descripcion AS description,
         a.runbook, json_extract(a.datos_json, '$.entities') AS entities, json_extract(a.datos_json, '$.evidence') AS evidence,
         r.dedup_hash, r.verdict, r.final_severity, r.severity_rationale, r.confidence, r.action, r.triaged_at, r.authorised_by
  FROM alerta a LEFT JOIN resultado_alerta r USING(alert_id);

CREATE VIEW v_alert_change_overlap AS
SELECT a.alert_id, c.context_key AS change_id, c.change_title, c.change_scope, c.change_detail,
       ROUND((julianday(c.change_end) - julianday(c.change_start)) * 24, 1) AS window_hours,
       EXISTS (SELECT 1 FROM bridge_alert_entity b
               WHERE b.alert_id = a.alert_id AND length(b.entity_value) > 3
                 AND (instr(lower(c.change_detail), lower(b.entity_value)) > 0
                   OR instr(lower(c.change_scope),  lower(b.entity_value)) > 0
                   OR instr(lower(c.change_title),  lower(b.entity_value)) > 0)) AS entity_match
FROM fact_alert a
JOIN dim_context c ON c.context_type = 'change'
 AND replace(substr(a.created_at,1,16),'T',' ') BETWEEN c.change_start AND c.change_end;

CREATE VIEW v_alert_duplicates AS
SELECT dedup_hash, COUNT(*) AS n, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen,
       GROUP_CONCAT(alert_id) AS alert_ids
FROM fact_alert GROUP BY dedup_hash HAVING COUNT(*) > 1;

CREATE VIEW v_alert_enriched AS
SELECT a.alert_id, a.created_at, a.source_product, a.rule_id, r.nombre AS rule_name, a.rule_severity,
       a.technique_id, m.technique, m.tactic, m.kill_chain_order,
       a.user_key, u.display_name, u.department, u.account_type, u.privileged, u.vip, u.hr_event,
       a.hostname, v.criticality AS asset_criticality, v.business_service, v.zone, v.open_vuln_count, v.max_cvss_open,
       a.context_key, c.reputation, c.malware_family, c.sandbox_verdict,
       (SELECT MAX(x.criticality_level) FROM bridge_alert_entity b JOIN dim_vulnerability x ON x.hostname=b.hostname
         WHERE b.alert_id=a.alert_id) AS max_asset_level,
       s.base_severity AS matrix_base_severity,
       a.runbook, r.runbook_checks, a.dedup_hash, a.verdict, a.final_severity, a.confidence
FROM fact_alert a
LEFT JOIN dim_rule r          ON r.rule_id = a.rule_id
LEFT JOIN dim_mitre m         ON m.technique_id = a.technique_id
LEFT JOIN dim_user u          ON u.user_key = a.user_key
LEFT JOIN dim_vulnerability v ON v.hostname = a.hostname
LEFT JOIN dim_context c       ON c.context_key = a.context_key
LEFT JOIN ref_severity_matrix s ON s.rule_severity = a.rule_severity
     AND s.criticality = COALESCE(v.criticality, CASE WHEN u.vip=1 OR u.privileged=1 THEN 'Alta' ELSE 'Media' END);

CREATE VIEW v_incident_queue AS
        SELECT incident_id, status, final_severity, title, alert_count, tactics_covered, max_kill_chain_stage,
               primary_user_key, primary_hostname, first_seen, last_seen, escalation_reasons, authorised_by,
               severity_rationale, related_incident_id,
               CASE final_severity WHEN 'critical' THEN '15 min' WHEN 'high' THEN '30 min' WHEN 'medium' THEN '4 h'
                    WHEN 'low' THEN '24 h' ELSE 'daily batch' END AS sla_triage,
               CASE final_severity WHEN 'critical' THEN datetime(first_seen, '+15 minutes')
                    WHEN 'high' THEN datetime(first_seen, '+30 minutes') WHEN 'medium' THEN datetime(first_seen, '+4 hours')
                    WHEN 'low' THEN datetime(first_seen, '+24 hours') END AS sla_due_utc
        FROM fact_incident
        ORDER BY CASE status WHEN 'escalate_n2' THEN 0 WHEN 'priority_triage' THEN 1 WHEN 'pending_triage' THEN 2
                             WHEN 'batch_review' THEN 3 ELSE 4 END,
                 CASE final_severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                 first_seen;

CREATE VIEW v_incident_timeline AS
SELECT s.incident_id, s.step_order, s.timestamp, m.kill_chain_order, m.tactic, s.technique_id, m.technique,
       s.evidence_origin, s.description, s.event_id, s.alert_id, s.user_key, s.hostname, s.confidence
FROM fact_attack_step s LEFT JOIN dim_mitre m ON m.technique_id = s.technique_id
ORDER BY s.incident_id, s.step_order;

CREATE TRIGGER fact_alert_update INSTEAD OF UPDATE ON fact_alert BEGIN
  INSERT INTO resultado_alerta(alert_id) SELECT NEW.alert_id WHERE NOT EXISTS (SELECT 1 FROM resultado_alerta WHERE alert_id = NEW.alert_id);
  UPDATE resultado_alerta SET verdict=NEW.verdict, final_severity=NEW.final_severity, severity_rationale=NEW.severity_rationale,
         confidence=NEW.confidence, action=NEW.action, triaged_at=NEW.triaged_at, authorised_by=NEW.authorised_by,
         dedup_hash=NEW.dedup_hash, user_key=NEW.user_key, hostname=NEW.hostname, context_key=NEW.context_key, event_id=NEW.event_id
  WHERE alert_id = NEW.alert_id;
END;
