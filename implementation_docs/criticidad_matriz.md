# Entradas a la matriz de severidad

El cálculo previo a los ajustes reúne las entidades explícitamente afectadas y selecciona la mayor criticidad conocida: Baja < Media < Alta < Crítica.

| Entrada | Cruce | Valor utilizado |
|---|---|---|
| Activos | `alert_assets.asset_id → assets.asset_id` | `assets.criticality`, de todos los activos vinculados |
| Servicios N:M | `asset_services.asset_id → assets.asset_id`, `asset_services.service_id → business_services.service_id` | `business_services.criticality`, de todos los servicios relacionados |
| Servicio principal | `assets.business_service → business_services.name` | Se conserva como entrada adicional, incluso si hay relaciones N:M |
| Servicio por producto | `alerts.rule_id → detection_rules.source_product → PRODUCT_SERVICES` | Criticidad del servicio configurado para WAF, ECOM, AI_GATEWAY, EMAIL_GW o IDP |
| Severidad original | `alerts.severity` | Fila de la matriz; no se sustituye por `detection_rules.base_severity` |

Las identidades se consultan como contexto, pero `vip` y `privileged` no son campos de criticidad y no se convierten en Alta para entrar en la matriz. La política los menciona en los ajustes posteriores de severidad, que quedan fuera de este paso.

Si no hay ninguna criticidad reconocida, se conserva Media como valor por defecto preexistente. No es un valor obtenido del inventario ni una regla establecida por la matriz; queda pendiente revisar el tratamiento de datos faltantes. La matriz procede de `docs/01_contexto/politica_soc.md`.

`prompt_builder.criticality` centraliza la selección y los servicios afectados. La selección del máximo y el cruce con la matriz se ejecutan en código y no requieren un modelo. El modo dataset lee también las relaciones revisadas de `implementation_docs/asset_services.csv`; sus identificadores de servicio siguen el orden del CSV de servicios, igual que la ingesta.

Los metadatos incluyen `criticality`, `criticality_origin` y `criticality_inputs`. Permiten revisar las criticidades de activos y servicios y qué entidad determinó el máximo. Las identidades y entidades no resueltas se conservan como contexto; sus atributos no añaden una criticidad.

## Relaciones adicionales documentadas

`src/criticality_scope.py` reúne las relaciones en consultas por lotes. SQLite y la lectura de los ficheros originales utilizan el mismo índice de relaciones. No se ejecuta un modelo para resolverlas.

La ruta principal de eventos es `alerts.alert_id → alert_events.event_id → tabla de detalle`. Se leen **todos los eventos citados**, aunque el filtrado de ruido los haya apartado. No se busca actividad de otras alertas ni eventos cercanos por tiempo.

| Tabla de detalle | Referencias a activos que se consultan |
|---|---|
| `ad_events_logs` | `dc_asset_id`, `source_asset_id` |
| `edr_logs` | `asset_id` |
| `proxy_logs` | `asset_id` |
| `dns_logs` | `asset_id` |
| `dlp_logs` | `asset_id` |
| `sql_audit_logs` | `client_asset_id` |
| `cicd_builds_logs` | `runner_asset_id` |

Ejemplo de la consulta de DLP (la clave de activo se resuelve contra el índice de `assets.asset_id`):

```sql
SELECT e.alert_id, t.event_id, t.asset_id, t.channel
FROM alert_events e
JOIN dlp_logs t ON t.event_id = e.event_id;
```

Los activos así obtenidos vuelven a cruzarse con **todos** sus servicios mediante `asset_services`. En firewall se consultan `src_ip` y `dst_ip` del evento citado contra `assets.ip`, conservando el papel de cada extremo. No se convierte una IP de `alert_indicators` en activo por mera coincidencia.

Para los servicios y dependencias que no tienen FK se usa [criticality_relations.csv](criticality_relations.csv). Cada fila declara el campo y valor exactos, el activo o servicio de destino y la documentación que sustenta el vínculo. **Este fichero no contiene criticidades**: se consultan siempre en el inventario.

| Recurso o fuente | Relación utilizada |
|---|---|
| `EMAIL_GW`, eventos `email` y `email_clicks` | Servicio «Correo y colaboración (SaaS)» |
| `IDP`, eventos `idp_signins`, `idp_audit` y `ad_events` | Servicio «Identidad y directorio activo» |
| `VPN`, eventos `vpn` | `VPN-GW01`, el concentrador registrado en el inventario |
| `idp_signins_logs.app` | Alias explícitos de aplicaciones: correo/colaboración, portal del empleado, ERP, directorio o VPN |
| `idp_audit_logs.target_resource` | Aplicación al principio de la ruta, como `Portal del Empleado/...` |
| `dlp_logs.channel = email` | Servicio de correo, además del equipo de `dlp_logs.asset_id` |
| `alert_cloud.bucket`, `cloudtrail_logs.request_parameters_json.bucketName` | Coincidencia exacta de `s3://bucket` con `business_services.asset_references` |
| `alert_cloud.identity`, `cloudtrail_logs.identity_name` | `svc_ecom_deploy → CI-RUNNER01`, porque su descripción de inventario identifica esa credencial de despliegue |
| `sql_audit_logs.database` | `CRM_PROD →` servicio de CRM, según la fuente de auditoría SQL del CRM |

Una dependencia de credencial o un extremo de red identifica un activo relacionado; no demuestra que ese equipo esté comprometido. No se atribuyen identidades cloud a `users` por igualdad de nombre, ni se considera afectado el equipo asignado a un usuario por el mero hecho de estar asignado. Tampoco se extraen relaciones arbitrarias de `evidence_json`, descripciones o comandos.

Los metadatos `criticality_inputs.relations` conservan cada vínculo con su papel, `event_id` y/o referencia documental. `unresolved_relations` muestra los destinos mencionados que no existen en el catálogo, sin crear servicios ni inventar criticidades.

## Comprobación de cobertura

Con la base local de 11.061 alertas, los 3.332 casos que antes no recuperaban ninguna criticidad obtienen ahora al menos una criticidad registrada: 2.297 de correo, 969 de identidad, 53 cloud, 10 VPN y 3 DLP. Ninguna alerta de esta base necesita el valor por defecto para el cálculo.

Eso no significa que todas las menciones del inventario tengan ficha de servicio. Persisten 56 referencias de alertas a valores de `assets.business_service` que no están entre los 14 servicios aprobados: por ejemplo, «Acceso remoto», «Impresión» o «Gestión de vulnerabilidades». En esos casos se conserva la criticidad propia del activo y cualquier otro servicio relacionado que sí exista. No se recuperan las fichas incompletas descartadas en el diseño de la base de datos.

Pruebas reproducibles: `python -m pytest tests/test_criticality_coverage.py`. Comprueban la cobertura sin valores por defecto, que todos los alias apunten a fichas existentes, la igualdad entre SQLite y los ficheros originales y el cruce de la matriz para todas las alertas en una copia en memoria.

Cada actualización del enriquecimiento recalcula las alertas existentes con el inventario, relaciones y matriz actuales. Las consultas se ejecutan por lotes y sin límites de filas. Esto actualiza las entradas derivadas; los tickets ya guardados necesitan un nuevo triaje para reflejar el cambio.

## Propiedad de la severidad

El modelo no calcula ni ajusta la severidad. Recibe el resultado de la matriz como contexto para el escalado, sin instrucciones de ajuste ni una herramienta para consultar la matriz. `severity` y `severity_rationale` no forman parte del esquema de su herramienta de entrega.

`src/severity.py` incorpora ambos campos al ticket con el resultado y la explicación calculados en código, antes de validar el formato y las obligaciones de escalado. Si una respuesta antigua o incorrecta intenta enviarlos, esos valores se sustituyen por los del sistema. Esto se aplica al adaptador API, Claude Code y al modo simulado. Si la matriz no se puede calcular, no se acepta una severidad alternativa del modelo.

La excepción del discriminador que asigna `informational` a ciertos cierres automáticos permanece como regla determinista existente; no la decide un modelo y queda fuera de esta retirada de la asignación de severidad al LLM. El resto del triaje y los datos originales de la política no se modifican.
