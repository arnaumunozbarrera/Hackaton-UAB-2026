# users

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `user_id` | `docs/02_inventario/usuarios.csv` → `user_id` | 1224 |
| `username` | `docs/02_inventario/usuarios.csv` → `username` | 1224 |
| `upn` | `docs/02_inventario/usuarios.csv` → `upn` | 1224 |
| `display_name` | `docs/02_inventario/usuarios.csv` → `display_name` | 1075 |
| `department` | `docs/02_inventario/usuarios.csv` → `department` | 13 |
| `title` | `docs/02_inventario/usuarios.csv` → `title` | 70 |
| `location` | `docs/02_inventario/usuarios.csv` → `location` | 33 |
| `manager_user_id` | `docs/02_inventario/usuarios.csv` → `manager_upn`; cruce con `upn` → `user_id` | 13 |
| `account_type` | `docs/02_inventario/usuarios.csv` → `account_type` | 4 |
| `privileged` | `docs/02_inventario/usuarios.csv` → `privileged` | 2 |
| `vip` | `docs/02_inventario/usuarios.csv` → `vip` | 2 |
| `mfa_method` | `docs/02_inventario/usuarios.csv` → `mfa_method` | 4 |
| `status` | `docs/02_inventario/usuarios.csv` → `status` | 1 |
| `created` | `docs/02_inventario/usuarios.csv` → `created` | 4 |
| `workstation_asset_id` | `docs/02_inventario/usuarios.csv` → `workstation`; cruce con `activos.csv.hostname` → `asset_id` | 1069 |
| `notes` | `docs/02_inventario/usuarios.csv` → `notes` | 16 |

Atributos aprobados: 16 atributos para 1224 cuentas. Valores únicos sin vacíos; las referencias se resuelven contra los identificadores de la tabla relacionada.

Relaciones, sin logs ni alertas:

| Tabla relacionada | Relación | Origen del vínculo |
|---|---|---|
| `users` | Responsable de otro usuario | `manager_user_id` → `users.user_id` |
| `assets` | Equipo asignado al usuario | `workstation_asset_id` → `assets.asset_id` |
| `assets` | Activos de los que el usuario es propietario | `activos.csv.owner_upn` → `usuarios.csv.upn`; se resolverá a `user_id` en activos |
| `hr_events` | Varios eventos de RR. HH. por usuario | `eventos_rrhh.csv.usuario` → `usuarios.csv.upn`; se resolverá a `user_id` en RR. HH. |

Los atributos de `assets` y `hr_events` se han aprobado abajo.

Cambios y tareas: `change_users.user_id` → `users.user_id`, solo para las cuentas mencionadas explícitamente en el calendario.

# assets

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `asset_id` | `docs/02_inventario/activos.csv` → `asset_id` | 1185 |
| `hostname` | `docs/02_inventario/activos.csv` → `hostname` | 1185 |
| `ip` | `docs/02_inventario/activos.csv` → `ip` | 1185 |
| `type` | `docs/02_inventario/activos.csv` → `type` | 20 |
| `os` | `docs/02_inventario/activos.csv` → `os` | 19 |
| `criticality` | `docs/02_inventario/activos.csv` → `criticality` | 4 |
| `zone_id` | `docs/02_inventario/activos.csv` → `zone` | 9 |
| `store_id` | `docs/02_inventario/activos.csv` → `ip`; pertenencia al rango `tiendas.csv.red` → `tienda` | 28 |
| `location` | `docs/02_inventario/activos.csv` → `location` | 33 |
| `business_service` | `docs/02_inventario/activos.csv` → `business_service` | 22 |
| `owner_user_id` | `docs/02_inventario/activos.csv` → `owner_upn`; cruce con `usuarios.csv.upn` → `user_id` | 1069 |
| `internet_facing` | `docs/02_inventario/activos.csv` → `internet_facing` | 2 |
| `edr_installed` | `docs/02_inventario/activos.csv` → `edr_installed` | 2 |
| `description` | `docs/02_inventario/activos.csv` → `description` | 5 |

Atributos aprobados: 1185 activos del inventario original. Valores únicos sin vacíos; 116 activos sin propietario informado. `owner_user_id` referencia `users.user_id`. Se descartan los tres recursos adicionales con ficha incompleta.

Relaciones: `users`, `network_zones`, `business_services` mediante `asset_services`, `vulnerabilities` y `stores` mediante `store_id` opcional.

# hr_events

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `hr_event_id` | Identificador generado al cargar, uno por evento | 17 previstos |
| `user_id` | `docs/02_inventario/eventos_rrhh.csv` → `usuario`; cruce con `usuarios.csv.upn` → `user_id` | 17 |
| `recorded_date` | `docs/02_inventario/eventos_rrhh.csv` → `fecha` | 9 |
| `event_type` | `docs/02_inventario/eventos_rrhh.csv` → `tipo` | 6 |
| `details` | `docs/02_inventario/eventos_rrhh.csv` → `detalle` | 10 |
| `effective_date` | `docs/02_inventario/eventos_rrhh.csv` → `fecha_efectiva` | 10 |

Atributos aprobados: 17 eventos. Valores únicos sin vacíos. Relación: `hr_events.user_id` → `users.user_id`; un usuario puede tener varios eventos.

# network_zones

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `zone_id` | `docs/02_inventario/zonas_red.csv` → `zona` | 10 |
| `cidr` | `docs/02_inventario/zonas_red.csv` → `cidr` | 10 |
| `location` | `docs/02_inventario/zonas_red.csv` → `ubicacion` | 7 |
| `description` | `docs/02_inventario/zonas_red.csv` → `descripcion` | 10 |

Atributos aprobados: 10 zonas. Relación: `assets.zone_id` → `network_zones.zone_id`.

`VPN-POOL` existe en el inventario de redes, aunque ningún activo del CSV tiene esa zona asignada. Se conserva como zona de conexiones VPN.

# business_services

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `service_id` | Identificador generado, uno por servicio del catálogo | 14 |
| `name` | `docs/02_inventario/servicios_negocio.csv` → `servicio` | 14 |
| `criticality` | `docs/02_inventario/servicios_negocio.csv` → `criticidad` | 3 |
| `impact` | `docs/02_inventario/servicios_negocio.csv` → `impacto` | 14 |
| `owner_role` | `docs/02_inventario/servicios_negocio.csv` → `responsable` | 7 |
| `asset_references` | `docs/02_inventario/servicios_negocio.csv` → `activos` | 14 |

Campos aprobados: 14 servicios del catálogo original. Se descartan los nueve servicios añadidos con ficha incompleta. `asset_references` conserva el texto fuente; los vínculos resueltos están en `asset_services`.

La criticidad del activo se conserva en `assets.criticality` y puede consultarse mediante la relación. No se copia automáticamente a `business_services.criticality`: la criticidad del servicio y la del activo son conceptos distintos; cualquier cálculo requerirá una regla acordada.

# asset_services

Aprobada; cada fila conecta un activo con un servicio. La pareja de identificadores no se repite.

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `asset_id` | `servicios_negocio.csv.activos` expandido contra el inventario y coincidencias con servicios del catálogo en `activos.csv.business_service` → `assets.asset_id` | 1178 |
| `service_id` | Servicio al que corresponde cada vínculo → `business_services.service_id` | 13 |

1180 pares distintos, sin patrones, en `asset_services.csv`, con solo `asset_id` y `service_id`. IDs de servicio 1–14 según el orden del catálogo. El servicio de correo no tiene activos enlazados en el inventario original.

La variante `Tienda online y app (≈38% de la facturación)` se vincula con `Tienda online y app`, sin crear otro servicio. Los originales de `docs/` no se modifican.

# vulnerabilities

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `vulnerability_id` | Identificador generado para cada registro | 46 previstos |
| `asset_id` | `docs/02_inventario/vulnerabilidades.csv` → `hostname`; cruce con `activos.csv.hostname` → `asset_id` | 46 |
| `reference` | `docs/02_inventario/vulnerabilidades.csv` → `id` | 9 |
| `product` | `docs/02_inventario/vulnerabilidades.csv` → `producto` | 9 |
| `cvss` | `docs/02_inventario/vulnerabilidades.csv` → `severidad_cvss` | 7 |
| `status` | `docs/02_inventario/vulnerabilidades.csv` → `estado` | 3 |
| `detected_date` | `docs/02_inventario/vulnerabilidades.csv` → `detectada` | 7 |
| `notes` | `docs/02_inventario/vulnerabilidades.csv` → `notas` | 7 |

Atributos aprobados: 46 registros. Valores únicos sin vacíos. Relación: `vulnerabilities.asset_id` → `assets.asset_id`; un activo puede tener varias vulnerabilidades. `reference` no siempre es un CVE y puede repetirse en varios activos. `cvss` conserva el texto fuente, incluida la indicación de estimación cuando existe.

# stores

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `store_id` | `docs/02_inventario/tiendas.csv` → `tienda` | 28 |
| `name` | `docs/02_inventario/tiendas.csv` → `nombre` | 28 |
| `city` | `docs/02_inventario/tiendas.csv` → `ciudad` | 24 |
| `cidr` | `docs/02_inventario/tiendas.csv` → `red` | 28 |

Atributos aprobados: 28 tiendas. Relación: `assets.store_id` → `stores.store_id`. Cada activo pertenece a 0..1 tienda; cada tienda tiene 0..N activos.

113 activos se vinculan por IP a las 28 tiendas, sin coincidencias ambiguas. Los 1072 restantes tienen `store_id = NULL`.

# changes

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `change_id` | `docs/02_inventario/calendario_cambios.csv` → `id` | 13 |
| `title` | `docs/02_inventario/calendario_cambios.csv` → `titulo` | 10 |
| `start_at` | `docs/02_inventario/calendario_cambios.csv` → `inicio` | 13 |
| `end_at` | `docs/02_inventario/calendario_cambios.csv` → `fin` | 12 |
| `requester` | `docs/02_inventario/calendario_cambios.csv` → `solicitante` | 5 |
| `details` | `docs/02_inventario/calendario_cambios.csv` → `detalle` | 11 |
| `scope` | `docs/02_inventario/calendario_cambios.csv` → `alcance` | 10 |

Atributos aprobados: 13 registros. Valores únicos sin vacíos. `requester` conserva el área u organización en texto. Las referencias explícitas se relacionan mediante `change_assets` y `change_users`; los alcances y condiciones generales permanecen en `scope` y `details`. Las fechas originales están expresadas en hora local; al cargar se convertirán a UTC.

# threat_intelligence

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `intelligence_id` | Identificador generado para cada registro | 409 previstos |
| `indicator_type` | `docs/05_inteligencia/ti_feed.jsonl` → `indicator_type` | 4 |
| `value` | `docs/05_inteligencia/ti_feed.jsonl` → `value` | 409 |
| `reputation` | `docs/05_inteligencia/ti_feed.jsonl` → `reputation` | 4 |
| `confidence` | `docs/05_inteligencia/ti_feed.jsonl` → `confidence` | 67 |
| `malware_family` | `docs/05_inteligencia/ti_feed.jsonl` → `malware_family` | 14 |
| `first_seen` | `docs/05_inteligencia/ti_feed.jsonl` → `first_seen` | 80 |
| `last_seen` | `docs/05_inteligencia/ti_feed.jsonl` → `last_seen` | 2 |
| `source` | `docs/05_inteligencia/ti_feed.jsonl` → `source` | 2 |
| `note` | `docs/05_inteligencia/ti_feed.jsonl` → `note` | 7 |

Atributos aprobados: 409 registros. Valores únicos sin vacíos. `tags` se separa en `threat_intelligence_tags`. No hay pares tipo–valor duplicados en la fuente.

Dato a revisar en la carga: `steamcommunity-profile-cdn.example` tiene `first_seen = 2026-10-17` y `last_seen = 2026-10-15`. Se conserva la fuente sin corregir por suposición.

# threat_intelligence_tags

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `intelligence_id` | Registro de `ti_feed.jsonl` al que pertenece la etiqueta → `threat_intelligence.intelligence_id` | 409 |
| `tag` | `docs/05_inteligencia/ti_feed.jsonl` → `tags`, separado por comas y sin espacios en los extremos | 19 |

Atributos aprobados: 424 pares distintos. Clave compuesta: (`intelligence_id`, `tag`). Cada registro de inteligencia puede tener varias etiquetas; cada etiqueta puede aparecer en varios registros.

# geoip

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `ip` | `docs/05_inteligencia/geoip_asn.csv` → `ip` | 86981 |
| `country` | `docs/05_inteligencia/geoip_asn.csv` → `country` | 22 |
| `city` | `docs/05_inteligencia/geoip_asn.csv` → `city` | 26 |
| `asn` | `docs/05_inteligencia/geoip_asn.csv` → `asn` | 44 |
| `as_org` | `docs/05_inteligencia/geoip_asn.csv` → `as_org` | 37 |
| `is_tor` | `docs/05_inteligencia/geoip_asn.csv` → `is_tor` | 2 |
| `is_vpn_provider` | `docs/05_inteligencia/geoip_asn.csv` → `is_vpn_provider` | 2 |
| `is_hosting` | `docs/05_inteligencia/geoip_asn.csv` → `is_hosting` | 2 |
| `is_residential_proxy` | `docs/05_inteligencia/geoip_asn.csv` → `is_residential_proxy` | 2 |

Atributos aprobados: 86981 registros. Clave primaria: `ip`. Valores únicos sin vacíos; 7195 registros sin ciudad. Campos `is_*`: sí/no.

Relación por coincidencia de `ip` con `threat_intelligence.value` cuando `indicator_type = ip`: 24 coincidencias actuales. Ambas tablas conservan sus registros sin correspondencia. La ubicación es aproximada; los indicadores de infraestructura no son un veredicto de maliciosidad.

# sandbox_reports

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `report_id` | Identificador generado por informe | 21 previstos |
| `sha256` | `docs/05_inteligencia/sandbox_informes.jsonl` → `sha256` | 21 |
| `md5` | `docs/05_inteligencia/sandbox_informes.jsonl` → `md5` | 21 |
| `file_name` | `docs/05_inteligencia/sandbox_informes.jsonl` → `file_name` | 21 |
| `verdict` | `docs/05_inteligencia/sandbox_informes.jsonl` → `verdict` | 4 |
| `score` | `docs/05_inteligencia/sandbox_informes.jsonl` → `score` | 15 |
| `malware_family` | `docs/05_inteligencia/sandbox_informes.jsonl` → `malware_family` | 14 |
| `analysis_env` | `docs/05_inteligencia/sandbox_informes.jsonl` → `analysis_env` | 1 |
| `analyzed_at` | `docs/05_inteligencia/sandbox_informes.jsonl` → `analyzed_at` | 1 |
| `note` | `docs/05_inteligencia/sandbox_informes.jsonl` → `note` | 4 |

Atributos aprobados: 21 informes. Clave primaria: `report_id`. Valores únicos sin vacíos. El veredicto corresponde al análisis del archivo, no al triaje de una alerta. Cruce con inteligencia por SHA-256 cuando `indicator_type = sha256`.

Separación aprobada en cuatro tablas relacionadas por `report_id`; sus atributos se revisarán a continuación:

- `sandbox_behaviors`: `behaviors[]`, 43 descripciones entre los informes.
- `sandbox_network_indicators`: `network.domains[]`, `network.ips[]` y `network.urls[]`, 16 referencias.
- `sandbox_mitre`: `mitre[]`, 24 asociaciones.
- `sandbox_dropped_files`: `dropped_files[]`, 2 archivos con nombre y SHA-256.

# sandbox_behaviors

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `report_id` | Informe de `sandbox_informes.jsonl` al que pertenece el comportamiento → `sandbox_reports.report_id` | 21 |
| `description` | `docs/05_inteligencia/sandbox_informes.jsonl` → cada elemento de `behaviors[]` | 38 |

Atributos aprobados: 43 registros. Clave compuesta: (`report_id`, `description`). Cada registro pertenece a un informe; cada informe puede tener varios comportamientos.

# sandbox_network_indicators

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `report_id` | Informe de `sandbox_informes.jsonl` al que pertenece el indicador → `sandbox_reports.report_id` | 9 |
| `indicator_type` | `docs/05_inteligencia/sandbox_informes.jsonl` → lista de origen: `network.domains` = `domain`, `network.ips` = `ip`, `network.urls` = `url` | 3 |
| `value` | `docs/05_inteligencia/sandbox_informes.jsonl` → cada elemento de `network.domains[]`, `network.ips[]` o `network.urls[]` | 13 |

Atributos aprobados: 16 registros en 9 informes. Clave compuesta: (`report_id`, `indicator_type`, `value`). Cruce con `threat_intelligence` por tipo y valor; con `geoip` por IP cuando corresponda.

# sandbox_mitre

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `report_id` | Informe de `sandbox_informes.jsonl` al que pertenece la técnica → `sandbox_reports.report_id` | 11 |
| `technique_id` | `docs/05_inteligencia/sandbox_informes.jsonl` → cada elemento de `mitre[]` | 20 |

Atributos aprobados: 24 asociaciones en 11 informes. Clave compuesta: (`report_id`, `technique_id`). Se conservan los códigos de la fuente, sin catálogo externo ni tabla adicional de técnicas. Se pueden comparar con `detection_rules.technique_id`; no todos tienen correspondencia en reglas.

# sandbox_dropped_files

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `report_id` | Informe de `sandbox_informes.jsonl` al que pertenece el archivo → `sandbox_reports.report_id` | 2 |
| `file_name` | `docs/05_inteligencia/sandbox_informes.jsonl` → `dropped_files[].name` | 2 |
| `sha256` | `docs/05_inteligencia/sandbox_informes.jsonl` → `dropped_files[].sha256` | 2 |

Atributos aprobados: 2 registros en 2 informes. Clave compuesta: (`report_id`, `file_name`, `sha256`). El SHA-256 permite cruzar con inteligencia u otros informes del mismo archivo.

# detection_rules

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `rule_id` | `docs/01_contexto/catalogo_casos_de_uso.csv` → `rule_id` | 44 |
| `name` | `docs/01_contexto/catalogo_casos_de_uso.csv` → `nombre` | 44 |
| `source_product` | `docs/01_contexto/catalogo_casos_de_uso.csv` → `fuente` | 14 |
| `base_severity` | `docs/01_contexto/catalogo_casos_de_uso.csv` → `severidad_base` | 4 |
| `tactic` | `docs/01_contexto/catalogo_casos_de_uso.csv` → `tactica` | 11 |
| `technique_id` | `docs/01_contexto/catalogo_casos_de_uso.csv` → `tecnica_id` | 42 |
| `technique_name` | `docs/01_contexto/catalogo_casos_de_uso.csv` → `tecnica` | 42 |
| `runbook_id` | `docs/01_contexto/catalogo_casos_de_uso.csv` → `runbook` | 10 |
| `detection_logic` | `docs/01_contexto/catalogo_casos_de_uso.csv` → `logica` | 44 |

Atributos aprobados: 44 reglas, clave primaria `rule_id`. Todos los campos están informados. `base_severity` es la severidad de la regla, no la final del triaje. `detection_logic` es texto descriptivo, no código ejecutable.

Relación: `runbook_id` → `runbooks.runbook_id`. Se conservan `tactic`, `technique_id` y `technique_name` tal como vienen en el catálogo. No se añaden datos externos ni tablas de referencia MITRE; la coincidencia de `technique_id` permite comparar con `sandbox_mitre`, sin exigir que todos sus códigos aparezcan en reglas.

# runbooks

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `runbook_id` | `docs/01_contexto/runbooks/RB-*.md` → código de la cabecera | 10 |
| `title` | `docs/01_contexto/runbooks/RB-*.md` → título de la cabecera, sin código | 10 |
| `checks_text` | `docs/01_contexto/runbooks/RB-*.md` → sección `Comprobaciones` | 10 |
| `decision_guidance_text` | `docs/01_contexto/runbooks/RB-*.md` → sección `Decisión` | 10 |

Atributos aprobados: 10 procedimientos, clave primaria `runbook_id`. Se conservan listas y saltos de línea de las dos secciones como texto. Son instrucciones de consulta, no reglas ejecutables ni comprobaciones ya realizadas.

Relación: `detection_rules.runbook_id` → `runbooks.runbook_id`; varias reglas pueden compartir un procedimiento.

# change_assets

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `change_id` | `docs/02_inventario/calendario_cambios.csv` → `id` | 9 |
| `asset_id` | Equipos explícitos en `alcance` y `detalle`, expandiendo rangos; cruce con `activos.csv.hostname` → `asset_id` | 18 |
| `role` | Papel indicado por `alcance` o por el texto de `detalle` | 3 |

22 vínculos en `change_assets.csv`. Clave compuesta: (`change_id`, `asset_id`, `role`). Roles: `target` = objetivo (16); `source` = origen (5); `access_path` = paso de acceso (1). Referencias a `changes.change_id` y `assets.asset_id`.

# change_users

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `change_id` | `docs/02_inventario/calendario_cambios.csv` → `id` | 6 |
| `user_id` | Cuenta explícita en `detalle`; cruce con `usuarios.csv.username` → `user_id` | 3 |

6 vínculos en `change_users.csv`. Clave compuesta: (`change_id`, `user_id`). Referencias a `changes.change_id` y `users.user_id`.

Ambos CSV son derivados de los originales. No se expanden alcances generales como «Todos los puestos» ni se atribuye una cuenta concreta a «cuenta adm». Las condiciones completas siguen en `changes`; un vínculo no demuestra por sí solo autorización.

# alerts

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `alert_id` | `docs/03_alertas/alertas.jsonl` → `alert_id` | 11061 |
| `created_at` | `docs/03_alertas/alertas.jsonl` → `created_at` | 11045 |
| `rule_id` | `docs/03_alertas/alertas.jsonl` → `rule_id` | 41 |
| `severity` | `docs/03_alertas/alertas.jsonl` → `severity` | 4 |
| `status` | `docs/03_alertas/alertas.jsonl` → `status` | 1 |
| `description` | `docs/03_alertas/alertas.jsonl` → `description` | 41 |
| `evidence_json` | `docs/03_alertas/alertas.jsonl` → objeto `evidence` completo | 4626 |
| `reported_user_count` | `docs/03_alertas/alertas.jsonl` → cantidad de `entities.users[].upn` cuando es «(12 cuentas)» o «(161 cuentas)» | 2 |

Atributos aprobados: 11061 alertas, clave primaria `alert_id`. Valores únicos sin vacíos. `reported_user_count` solo se informa en las 62 alertas con cantidades agregadas; no se inventan identidades. `severity` conserva la severidad recibida, no el resultado del triaje.

Relación: `alerts.rule_id` → `detection_rules.rule_id`. De la regla obtenemos nombre, producto, táctica, código y nombre de técnica, y `runbook_id` → `runbooks.runbook_id`. Todos coinciden con el JSONL actual; no se duplican en `alerts`.

No se guarda `entities_json`: sus diez bloques se representan en las tablas siguientes y en `reported_user_count`. `evidence_json` conserva su estructura original (169 campos distintos según detección); puede incluir menciones a entidades como parte de la evidencia. En una alerta, las 161 cuentas también constan en `evidence.distinct_accounts`; `failed_attempts` no se interpreta como número de cuentas.

# alert_users

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `alert_id` | `docs/03_alertas/alertas.jsonl` → `alert_id` del usuario observado | 4235 |
| `user_id` | `entities.users[].upn`; cruce con `docs/02_inventario/usuarios.csv.upn` → `user_id` | 1029 |

4237 vínculos. Clave compuesta: (`alert_id`, `user_id`). Referencias a `alerts` y `users`. Los nombres y UPN informados coinciden con el directorio y se consultan allí. Las 62 referencias agregadas van en `alerts.reported_user_count`.

# alert_assets

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `alert_id` | `docs/03_alertas/alertas.jsonl` → `alert_id` del equipo observado | 3818 |
| `asset_id` | `entities.hosts[].hostname`; cruce con `docs/02_inventario/activos.csv.hostname` → `asset_id` | 1026 |

3825 vínculos. Clave compuesta: (`alert_id`, `asset_id`). Referencias a `alerts` y `assets`. Todas las referencias encuentran activo; hostname e IP coinciden con inventario y no se duplican.

# alert_indicators

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `alert_id` | `docs/03_alertas/alertas.jsonl` → `alert_id` del indicador observado | 8658 |
| `indicator_type` | Lista de origen: `entities.ips` = `ip`, `entities.domains` = `domain`, `entities.urls` = `url` | 3 |
| `value` | Cada elemento de `entities.ips[]`, `entities.domains[]` y `entities.urls[]`, expandiendo el rango IP | 4923 |

13022 vínculos. Clave compuesta: (`alert_id`, `indicator_type`, `value`). Referencia a `alerts`. Se conservan aunque no existan en inteligencia. Cruces opcionales con `threat_intelligence` por tipo y valor, y `geoip` por IP; no se exige correspondencia.

El valor original `10.40.16.21-26` aparece una vez y se expande a seis direcciones `10.40.16.21`…`10.40.16.26`. Los hashes de archivos se guardan en `alert_files`, no se duplican aquí.

# alert_files

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `alert_id` | `docs/03_alertas/alertas.jsonl` → `alert_id` del archivo observado | 425 |
| `position` | Índice desde 0 del elemento en `entities.files[]` | 2 |
| `file_name` | `docs/03_alertas/alertas.jsonl` → `entities.files[].name` | 18 |
| `sha256` | `docs/03_alertas/alertas.jsonl` → `entities.files[].sha256` | 17 |
| `path` | `docs/03_alertas/alertas.jsonl` → `entities.files[].path` | 5 |

427 registros. Clave compuesta: (`alert_id`, `position`); referencia a `alerts`. `path` solo se informa en 7 registros. Se conservan los nombres observados aunque coincida el hash. Cruces por SHA-256 con `sandbox_reports` y con `threat_intelligence` de tipo `sha256`, sin exigir coincidencia.

# alert_processes

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `alert_id` | `docs/03_alertas/alertas.jsonl` → `alert_id` del proceso observado | 1884 |
| `position` | Índice desde 0 del elemento en `entities.processes[]` | 2 |
| `name` | `docs/03_alertas/alertas.jsonl` → `entities.processes[].name` | 8 |
| `parent_name` | `docs/03_alertas/alertas.jsonl` → `entities.processes[].parent` | 3 |
| `command_line` | `docs/03_alertas/alertas.jsonl` → `entities.processes[].command_line` | 6 |
| `pid` | `docs/03_alertas/alertas.jsonl` → `entities.processes[].pid` | 3 |

1886 registros. Clave compuesta: (`alert_id`, `position`); referencia a `alerts`. Campos ausentes → `NULL`. Se conserva el proceso observado; ni su nombre ni el PID identifican un proceso globalmente.

# alert_customers

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `alert_id` | `docs/03_alertas/alertas.jsonl` → `alert_id` del cliente observado | 428 |
| `position` | Índice desde 0 del elemento en `entities.customers[]` | 2 |
| `customer_id` | `docs/03_alertas/alertas.jsonl` → `entities.customers[].customer_id` | 425 |
| `role` | `docs/03_alertas/alertas.jsonl` → `entities.customers[].role` | 1 |

429 registros. Clave compuesta: (`alert_id`, `position`); referencia a `alerts`. `role` solo se informa una vez («víctima»). `customer_id` no referencia `users`; permite consultar eventos en `ecom_auth_logs`, `ecom_account_logs` y `ai_gateway_logs` por ese mismo identificador, sin FK obligatoria.

# alert_cloud

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `alert_id` | `docs/03_alertas/alertas.jsonl` → `alert_id` del bloque cloud | 53 |
| `cloud_account` | `docs/03_alertas/alertas.jsonl` → `entities.cloud.account` | 1 |
| `identity` | `docs/03_alertas/alertas.jsonl` → `entities.cloud.identity` | 2 |
| `bucket` | `docs/03_alertas/alertas.jsonl` → `entities.cloud.bucket` | 2 |
| `access_key` | `docs/03_alertas/alertas.jsonl` → `entities.cloud.access_key` | 1 |
| `new_user` | `docs/03_alertas/alertas.jsonl` → `entities.cloud.new_user` | 1 |

53 registros. `alert_id` es clave primaria y referencia a `alerts`; cada alerta tiene 0..1 bloque cloud. Campos ausentes → `NULL`. Son nombres observados en el entorno cloud, sin atribuirlos automáticamente a usuarios o activos del inventario. Permiten buscar coincidencias en `cloudtrail_logs.identity_name`, `access_key_id` y sus parámetros JSON; no son FK obligatorias.

# alert_ai_sessions

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `alert_id` | `docs/03_alertas/alertas.jsonl` → `alert_id` de la sesión observada | 3 |
| `session_id` | `docs/03_alertas/alertas.jsonl` → `entities.ai_session` | 2 |

3 registros. `alert_id` es clave primaria y referencia a `alerts`; cada alerta tiene 0..1 sesión de IA. Una sesión puede aparecer en varias alertas. Cruce con `ai_gateway_logs.session_id`: las dos sesiones existen y pueden tener varios eventos; no se usa una FK hacia esa columna no única.

# alert_events

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `alert_id` | `docs/03_alertas/alertas.jsonl` → `alert_id` que referencia el evento | 11060 |
| `position` | Índice desde 0 del elemento en `related_events[]` | 18 |
| `event_id` | `docs/03_alertas/alertas.jsonl` → cada elemento de `related_events[]` | 15650 |

15683 vínculos. Clave compuesta: (`alert_id`, `position`). Referencias a `alerts.alert_id` y `logs.event_id`. Se conserva el orden de la lista original; todos los eventos referenciados existen en los logs de `docs/04_logs/`. Un evento puede aparecer en varias alertas.

# logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/` → `event_id` de cada registro de las 18 fuentes originales CSV/JSONL | 814471 |
| `timestamp` | `docs/04_logs/` → `timestamp` de cada registro | 745976 |
| `source` | Nombre del fichero original sin extensión, por ejemplo `vpn` o `edr_events` | 18 |

Estructura común aprobada: 814471 eventos. Clave primaria: `event_id`, sin duplicados entre fuentes ni valores vacíos. Todos tienen fecha informada. No se utiliza `combined_master_logs.csv` como fuente adicional para evitar duplicados.

Cada evento tendrá una fila en `logs` y una en su tabla de detalle, conectadas por `event_id`. Fecha y fuente se guardan solo en `logs`; los demás atributos se revisan por fuente. Las alertas se conectan mediante `alert_events.event_id` → `logs.event_id`.

Reglas comunes para las tablas de detalle: los campos `*_user_id` referencian `users.user_id` y los campos `*_asset_id` referencian `assets.asset_id`, salvo aclaración específica. Una referencia resuelta y su texto sin resolver (`unresolved` o `target_resource`) son alternativas: se informa el ID o el texto original no identificado, nunca ambos. No se crean usuarios ni activos ficticios. Los nombres y UPN resueltos se consultan en sus inventarios.

Los campos `*_json` conservan objetos variables completos, incluidos objetos vacíos; no se duplican sus atributos en columnas adicionales. Las listas separadas conservan orden mediante `position` desde 0; listas vacías producen cero filas. Campos escalares ausentes o vacíos → `NULL`; `0` y `False` son datos válidos. Los recuentos de valores únicos excluyen vacíos.

Las IPs observadas pueden cruzarse opcionalmente con `geoip.ip`; dominios, URLs y hashes con `threat_intelligence` por tipo y valor, y hashes con `sandbox_reports.sha256`. No se exige coincidencia ni se interpreta un indicador ausente como benigno. País, ciudad y ASN del evento se conservan como observaciones, sin sustituirlos por el enriquecimiento de GeoIP. Coincidencias de IP, sesión, cliente, build o identidad cloud son claves de consulta, no FK obligatorias ni prueba de una misma persona.

# vpn_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/vpn.jsonl` → `event_id` | 9821 |
| `user_id` | `docs/04_logs/vpn.jsonl` → `user`; cruce con `usuarios.csv.username` → `user_id` | 1091 |
| `src_ip` | `docs/04_logs/vpn.jsonl` → `src_ip` | 1074 |
| `assigned_ip` | `docs/04_logs/vpn.jsonl` → `assigned_ip` | 3092 |
| `action` | `docs/04_logs/vpn.jsonl` → `action` | 3 |
| `country` | `docs/04_logs/vpn.jsonl` → `country` | 16 |
| `bytes` | `docs/04_logs/vpn.jsonl` → `bytes` | 826 |
| `mfa_result` | `docs/04_logs/vpn.jsonl` → `mfa_result` | 3 |

9821 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = vpn`. `user_id` → `users.user_id`: todas las cuentas están identificadas. `assigned_ip` es una asignación VPN, no un activo fijo. Hay 167 IPs asignadas y 4988 resultados MFA vacíos. Acciones: `connect`, `disconnect`, `auth_fail`.

# idp_signins_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/idp_signins.jsonl` → `event_id` | 76713 |
| `user_id` | `docs/04_logs/idp_signins.jsonl` → `user_upn`; cruce con `usuarios.csv.upn` → `user_id` | 1211 |
| `app` | `docs/04_logs/idp_signins.jsonl` → `app` | 7 |
| `result` | `docs/04_logs/idp_signins.jsonl` → `result` | 2 |
| `failure_reason` | `docs/04_logs/idp_signins.jsonl` → `failure_reason` | 3 |
| `mfa_method` | `docs/04_logs/idp_signins.jsonl` → `mfa_method` | 4 |
| `mfa_result` | `docs/04_logs/idp_signins.jsonl` → `mfa_result` | 7 |
| `src_ip` | `docs/04_logs/idp_signins.jsonl` → `src_ip` | 3102 |
| `country` | `docs/04_logs/idp_signins.jsonl` → `country` | 16 |
| `city` | `docs/04_logs/idp_signins.jsonl` → `city` | 29 |
| `asn` | `docs/04_logs/idp_signins.jsonl` → `asn` | 26 |
| `user_agent` | `docs/04_logs/idp_signins.jsonl` → `user_agent` | 6 |
| `device_id` | `docs/04_logs/idp_signins.jsonl` → `device_id` | 2277 |
| `device_compliant` | `docs/04_logs/idp_signins.jsonl` → `device_compliant` | 2 |
| `session_id` | `docs/04_logs/idp_signins.jsonl` → `session_id` | 28795 |
| `risk_level` | `docs/04_logs/idp_signins.jsonl` → `risk_level` | 4 |
| `conditional_access` | `docs/04_logs/idp_signins.jsonl` → `conditional_access` | 3 |

76713 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = idp_signins`. `user_id` → `users.user_id`: todas las cuentas se resuelven. `device_id` es un identificador del IdP y no se equipara automáticamente con un activo. `session_id` agrupa accesos cuando está informado, pero no es clave única. Se conserva la geolocalización observada en el evento.

# idp_audit_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/idp_audit.jsonl` → `event_id` | 762 |
| `actor_user_id` | `docs/04_logs/idp_audit.jsonl` → `actor_upn`; cruce con `usuarios.csv.upn` → `user_id` | 509 |
| `operation` | `docs/04_logs/idp_audit.jsonl` → `operation` | 7 |
| `target_user_id` | `docs/04_logs/idp_audit.jsonl` → `target`; cruce con `usuarios.csv.upn` → `user_id` | 366 |
| `target_resource` | `docs/04_logs/idp_audit.jsonl` → `target`, solo si no corresponde a `users` | 5 |
| `src_ip` | `docs/04_logs/idp_audit.jsonl` → `src_ip` | 3 |
| `details_json` | `docs/04_logs/idp_audit.jsonl` → `details` | 73 |

762 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = idp_audit`. `actor_user_id` y `target_user_id` → `users.user_id`. El actor siempre se resuelve; 263 objetivos son aplicaciones o recursos, conservados en `target_resource` (5 valores), sin inventar usuarios. `details_json` conserva los atributos variables de cada operación.

# ad_events_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/ad_events.jsonl` → `event_id` | 526 |
| `dc_asset_id` | `docs/04_logs/ad_events.jsonl` → `dc`; cruce con `activos.csv.hostname` → `asset_id` | 2 |
| `event_code` | `docs/04_logs/ad_events.jsonl` → `event_code` | 6 |
| `event_description` | `docs/04_logs/ad_events.jsonl` → `event` | 6 |
| `subject_user_id` | `docs/04_logs/ad_events.jsonl` → `subject`; cruce con `usuarios.csv.username` → `user_id` | 164 |
| `subject_unresolved` | `docs/04_logs/ad_events.jsonl` → `subject`, solo si no corresponde a `users` | 1 |
| `target_user_id` | `docs/04_logs/ad_events.jsonl` → `target`; cruce con `usuarios.csv.username` → `user_id` | 413 |
| `target_unresolved` | `docs/04_logs/ad_events.jsonl` → `target`, solo si no corresponde a `users` | 1 |
| `source_asset_id` | `docs/04_logs/ad_events.jsonl` → `src_host`; cruce con `activos.csv.hostname` → `asset_id` | 4 |
| `details_json` | `docs/04_logs/ad_events.jsonl` → `details` | 3 |

526 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = ad_events`. `dc_asset_id` y `source_asset_id` → `assets.asset_id`; ambas cuentas resueltas → `users.user_id`. Se conservan `helpdesk.portal` como actor no inventariado (190 eventos) y `adm2.aferrer` como objetivo no inventariado (1). `details_json` conserva grupo, descripción y configuración de contraseña cuando aparecen.

# edr_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/edr_events.jsonl` → `event_id` | 112492 |
| `event_type` | `docs/04_logs/edr_events.jsonl` → `event_type` | 8 |
| `asset_id` | `docs/04_logs/edr_events.jsonl` → `hostname`; cruce con `activos.csv.hostname` → `asset_id` | 1083 |
| `user_id` | `docs/04_logs/edr_events.jsonl` → `user`; cruce con `usuarios.csv.username` → `user_id` | 1073 |
| `unresolved_user` | `docs/04_logs/edr_events.jsonl` → `user`, solo si no corresponde a `users` | 2 |
| `process_name` | `docs/04_logs/edr_events.jsonl` → `process_name` | 41 |
| `process_path` | `docs/04_logs/edr_events.jsonl` → `process_path` | 427 |
| `command_line` | `docs/04_logs/edr_events.jsonl` → `command_line` | 40 |
| `parent_name` | `docs/04_logs/edr_events.jsonl` → `parent_name` | 16 |
| `pid` | `docs/04_logs/edr_events.jsonl` → `pid` | 28397 |
| `parent_pid` | `docs/04_logs/edr_events.jsonl` → `parent_pid` | 8504 |
| `sha256` | `docs/04_logs/edr_events.jsonl` → `sha256` | 33 |
| `signer` | `docs/04_logs/edr_events.jsonl` → `signer` | 8 |
| `integrity` | `docs/04_logs/edr_events.jsonl` → `integrity` | 3 |
| `details_json` | `docs/04_logs/edr_events.jsonl` → `details` | 28 |

112492 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = edr_events`. `asset_id` → `assets.asset_id`; `user_id` → `users.user_id` cuando se identifica. Solo se elimina el prefijo de dominio conocido `TARVIA` para resolver cuentas. `NT AUTHORITY\SYSTEM` y `jenkins` se conservan en `unresolved_user` (1358 eventos); 7 eventos no indican usuario. `details_json` conserva los detalles variables. PID y nombre de proceso no son identificadores globales. Cruces por SHA-256 con inteligencia y sandbox.

# proxy_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/proxy.csv` → `event_id` | 194258 |
| `src_ip` | `docs/04_logs/proxy.csv` → `src_ip` | 1072 |
| `asset_id` | `docs/04_logs/proxy.csv` → `hostname`; cruce con `activos.csv.hostname` → `asset_id` | 1072 |
| `user_id` | `docs/04_logs/proxy.csv` → `user`; cruce con `usuarios.csv.username` → `user_id` | 1069 |
| `unresolved_user` | `docs/04_logs/proxy.csv` → `user`, solo si no corresponde a `users` | 1 |
| `method` | `docs/04_logs/proxy.csv` → `method` | 2 |
| `url` | `docs/04_logs/proxy.csv` → `url` | 16554 |
| `domain` | `docs/04_logs/proxy.csv` → `domain` | 60 |
| `dst_ip` | `docs/04_logs/proxy.csv` → `dst_ip` | 341 |
| `http_status` | `docs/04_logs/proxy.csv` → `status` | 4 |
| `bytes_out` | `docs/04_logs/proxy.csv` → `bytes_out` | 3842 |
| `bytes_in` | `docs/04_logs/proxy.csv` → `bytes_in` | 170842 |
| `category` | `docs/04_logs/proxy.csv` → `category` | 26 |
| `action` | `docs/04_logs/proxy.csv` → `action` | 1 |
| `user_agent` | `docs/04_logs/proxy.csv` → `user_agent` | 4 |

194258 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = proxy`. `asset_id` → `assets.asset_id`; `user_id` → `users.user_id` cuando se resuelve. Los 136 eventos con `user = SYSTEM` conservan ese texto en `unresolved_user`. Dominio y URL son valores observados; el dominio de clasificación del proxy se conserva, sin recalcularlo desde la URL.

# dns_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/dns.csv` → `event_id` | 178221 |
| `src_ip` | `docs/04_logs/dns.csv` → `src_ip` | 1070 |
| `asset_id` | `docs/04_logs/dns.csv` → `hostname`; cruce con `activos.csv.hostname` → `asset_id` | 1070 |
| `query` | `docs/04_logs/dns.csv` → `query` | 4014 |
| `qtype` | `docs/04_logs/dns.csv` → `qtype` | 2 |
| `response` | `docs/04_logs/dns.csv` → `response` | 607 |
| `rcode` | `docs/04_logs/dns.csv` → `rcode` | 1 |

178221 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = dns`. `asset_id` → `assets.asset_id`: todos los equipos se identifican. `response` conserva el texto de la respuesta; no se fuerza como FK de una única IP. `query` permite buscar coincidencias con dominios de inteligencia; no se exige que existan en el feed.

# firewall_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/firewall.csv` → `event_id` | 24648 |
| `src_ip` | `docs/04_logs/firewall.csv` → `src_ip` | 226 |
| `src_port` | `docs/04_logs/firewall.csv` → `src_port` | 13234 |
| `dst_ip` | `docs/04_logs/firewall.csv` → `dst_ip` | 1442 |
| `dst_port` | `docs/04_logs/firewall.csv` → `dst_port` | 16 |
| `proto` | `docs/04_logs/firewall.csv` → `proto` | 1 |
| `action` | `docs/04_logs/firewall.csv` → `action` | 2 |
| `firewall_rule` | `docs/04_logs/firewall.csv` → `rule` | 13 |
| `bytes` | `docs/04_logs/firewall.csv` → `bytes` | 23112 |
| `src_zone_id` | `docs/04_logs/firewall.csv` → `zone_src`, si coincide con `network_zones.zone_id` | 8 |
| `dst_zone_id` | `docs/04_logs/firewall.csv` → `zone_dst`, si coincide con `network_zones.zone_id` | 6 |
| `dst_zone_unresolved` | `docs/04_logs/firewall.csv` → `zone_dst`, si no existe en `network_zones` | 2 |

24648 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = firewall`. `src_zone_id` y `dst_zone_id` → `network_zones.zone_id` cuando existen. Los destinos `ANY` y `EXTERNAL` se conservan en `dst_zone_unresolved`, sin crear zonas ficticias. `firewall_rule` es una regla de cortafuegos, no `detection_rules.rule_id`. No se atribuyen usuarios o activos solo por una IP.

# email_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/email.jsonl` → `event_id` | 56797 |
| `direction` | `docs/04_logs/email.jsonl` → `direction` | 3 |
| `message_id` | `docs/04_logs/email.jsonl` → `message_id` | 56797 |
| `sender_user_id` | `docs/04_logs/email.jsonl` → `sender`; cruce con `usuarios.csv.upn` → `user_id` | 2 |
| `sender_unresolved` | `docs/04_logs/email.jsonl` → `sender`, solo si no corresponde a `users` | 20 |
| `subject` | `docs/04_logs/email.jsonl` → `subject` | 15892 |
| `verdict` | `docs/04_logs/email.jsonl` → `verdict` | 4 |
| `action` | `docs/04_logs/email.jsonl` → `action` | 1 |
| `spf` | `docs/04_logs/email.jsonl` → `spf` | 3 |
| `dkim` | `docs/04_logs/email.jsonl` → `dkim` | 2 |
| `dmarc` | `docs/04_logs/email.jsonl` → `dmarc` | 3 |
| `sender_ip` | `docs/04_logs/email.jsonl` → `sender_ip` | 2303 |
| `body_excerpt` | `docs/04_logs/email.jsonl` → `body_excerpt` | 2 |

56797 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = email`. `message_id` es único en esta fuente. `sender_user_id` → `users.user_id` solo para los remitentes identificados (2 eventos); `sender_unresolved` conserva los otros 20 valores, incluidos buzones corporativos no inventariados. Destinatarios, adjuntos y URLs van en tablas hijas; no se duplican como JSON. `body_excerpt` es un extracto, no el correo completo.

# email_recipients

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/email.jsonl` → `event_id` del mensaje | 56797 |
| `position` | Índice desde 0 del elemento en `recipients[]` | 1 |
| `recipient_user_id` | `docs/04_logs/email.jsonl` → `recipients[]`; cruce con `usuarios.csv.upn` → `user_id` | 1069 |
| `recipient_unresolved` | `docs/04_logs/email.jsonl` → `recipients[]`, solo para direcciones no inventariadas | 1 |

56797 destinatarios. Clave compuesta: (`event_id`, `position`); `event_id` → `email_logs.event_id`, `recipient_user_id` → `users.user_id`. Solo una dirección no encuentra usuario y se conserva en `recipient_unresolved`. No se repite el UPN de destinatarios ya identificados.

# email_attachments

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/email.jsonl` → `event_id` del adjunto | 3 |
| `position` | Índice desde 0 del elemento en `attachments[]` | 1 |
| `file_name` | `docs/04_logs/email.jsonl` → `attachments[].name` | 3 |
| `sha256` | `docs/04_logs/email.jsonl` → `attachments[].sha256` | 3 |
| `size` | `docs/04_logs/email.jsonl` → `attachments[].size` | 3 |

3 adjuntos. Clave compuesta: (`event_id`, `position`); `event_id` → `email_logs.event_id`. Cruce por SHA-256 con inteligencia y sandbox. La lista opcional `contains[]` se representa en `email_attachment_contents`.

# email_attachment_contents

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/email.jsonl` → `event_id` del mensaje | 1 |
| `attachment_position` | Índice desde 0 del adjunto en `attachments[]` | 1 |
| `position` | Índice desde 0 del elemento en `attachments[].contains[]` | 1 |
| `file_name` | `docs/04_logs/email.jsonl` → `attachments[].contains[].name` | 1 |
| `sha256` | `docs/04_logs/email.jsonl` → `attachments[].contains[].sha256` | 1 |

1 archivo contenido en un adjunto. Clave compuesta: (`event_id`, `attachment_position`, `position`). (`event_id`, `attachment_position`) → `email_attachments(event_id, position)`. El hash del archivo interior es distinto del hash del adjunto contenedor.

# email_urls

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/email.jsonl` → `event_id` del mensaje | 56794 |
| `position` | Índice desde 0 del elemento en `urls[]` | 1 |
| `url` | `docs/04_logs/email.jsonl` → cada elemento de `urls[]` | 56781 |

56794 URLs. Clave compuesta: (`event_id`, `position`); `event_id` → `email_logs.event_id`. Permiten coincidencias con inteligencia y navegación; no se exige que tengan reputación conocida.

# email_clicks_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/email_clicks.jsonl` → `event_id` | 16249 |
| `user_id` | `docs/04_logs/email_clicks.jsonl` → `user`; cruce con `usuarios.csv.upn` → `user_id` | 1069 |
| `url` | `docs/04_logs/email_clicks.jsonl` → `url` | 16249 |
| `email_event_id` | `docs/04_logs/email_clicks.jsonl` → `message_id`; cruce con `email.jsonl.message_id` → `event_id` | 16249 |
| `action` | `docs/04_logs/email_clicks.jsonl` → `action` | 1 |
| `verdict_at_click` | `docs/04_logs/email_clicks.jsonl` → `verdict_at_click` | 2 |
| `src_ip` | `docs/04_logs/email_clicks.jsonl` → `src_ip` | 1069 |

16249 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = email_clicks`. `user_id` → `users.user_id`; `email_event_id` → `email_logs.event_id`. Todos los usuarios y mensajes se resuelven. No se duplica el `message_id`, consultable en el mensaje original. URL, acción y veredicto corresponden al momento del clic, no necesariamente a la entrega.

# dlp_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/dlp.jsonl` → `event_id` | 1042 |
| `user_id` | `docs/04_logs/dlp.jsonl` → `user`; cruce con `usuarios.csv.username` → `user_id` | 648 |
| `asset_id` | `docs/04_logs/dlp.jsonl` → `hostname`; cruce con `activos.csv.hostname` → `asset_id` | 648 |
| `channel` | `docs/04_logs/dlp.jsonl` → `channel` | 3 |
| `destination` | `docs/04_logs/dlp.jsonl` → `destination` | 8 |
| `file_name` | `docs/04_logs/dlp.jsonl` → `file_name` | 9 |
| `file_size` | `docs/04_logs/dlp.jsonl` → `file_size` | 1040 |
| `policy` | `docs/04_logs/dlp.jsonl` → `policy` | 4 |
| `matches_json` | `docs/04_logs/dlp.jsonl` → `matches` | 3 |
| `action` | `docs/04_logs/dlp.jsonl` → `action` | 1 |

1042 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = dlp`. `user_id` → `users.user_id` y `asset_id` → `assets.asset_id`: todas las referencias se resuelven. `matches_json` conserva los recuentos y notas de datos sensibles; no se interpreta como datos de contacto del usuario. `destination` puede ser dirección de correo, dominio u otro destino: se conserva el valor observado.

# sql_audit_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/sql_audit.jsonl` → `event_id` | 3924 |
| `user_id` | `docs/04_logs/sql_audit.jsonl` → `user`; cruce con `usuarios.csv.username` → `user_id` | 2 |
| `client_asset_id` | `docs/04_logs/sql_audit.jsonl` → `client_host`; cruce con `activos.csv.hostname` → `asset_id` | 2 |
| `database` | `docs/04_logs/sql_audit.jsonl` → `database` | 1 |
| `statement_type` | `docs/04_logs/sql_audit.jsonl` → `statement_type` | 1 |
| `object` | `docs/04_logs/sql_audit.jsonl` → `object` | 4 |
| `rows_returned` | `docs/04_logs/sql_audit.jsonl` → `rows_returned` | 62 |
| `statement` | `docs/04_logs/sql_audit.jsonl` → `statement` | 4 |

3924 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = sql_audit`. `user_id` → `users.user_id`; `client_asset_id` → `assets.asset_id`: todas las referencias se resuelven. El usuario es la cuenta que accede a SQL; no se atribuye automáticamente la operación a una persona detrás de una aplicación. La sentencia se conserva solo cuando viene informada.

# waf_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/waf.jsonl` → `event_id` | 71421 |
| `src_ip` | `docs/04_logs/waf.jsonl` → `src_ip` | 22166 |
| `country` | `docs/04_logs/waf.jsonl` → `country` | 12 |
| `method` | `docs/04_logs/waf.jsonl` → `method` | 2 |
| `host` | `docs/04_logs/waf.jsonl` → `host` | 2 |
| `uri` | `docs/04_logs/waf.jsonl` → `uri` | 17 |
| `http_status` | `docs/04_logs/waf.jsonl` → `status` | 3 |
| `waf_rule_id` | `docs/04_logs/waf.jsonl` → `rule_id` | 8 |
| `waf_rule_message` | `docs/04_logs/waf.jsonl` → `rule_msg` | 9 |
| `action` | `docs/04_logs/waf.jsonl` → `action` | 2 |
| `user_agent` | `docs/04_logs/waf.jsonl` → `user_agent` | 9 |
| `bytes` | `docs/04_logs/waf.jsonl` → `bytes` | 13478 |

71421 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = waf`. `host` identifica el sitio web solicitado, no el hostname de un activo inventariado. `waf_rule_id` identifica una firma del WAF; no es `detection_rules.rule_id`. No se inventa usuario autenticado a partir de la IP. País y dirección corresponden a la observación de la petición.

# ecom_auth_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/ecom_auth.jsonl` → `event_id` | 44064 |
| `customer_id` | `docs/04_logs/ecom_auth.jsonl` → `customer_id` | 17549 |
| `email` | `docs/04_logs/ecom_auth.jsonl` → `email` | 19067 |
| `src_ip` | `docs/04_logs/ecom_auth.jsonl` → `src_ip` | 17467 |
| `result` | `docs/04_logs/ecom_auth.jsonl` → `result` | 2 |
| `failure_reason` | `docs/04_logs/ecom_auth.jsonl` → `failure_reason` | 3 |
| `user_agent` | `docs/04_logs/ecom_auth.jsonl` → `user_agent` | 6 |
| `device_fp` | `docs/04_logs/ecom_auth.jsonl` → `device_fp` | 17352 |
| `captcha` | `docs/04_logs/ecom_auth.jsonl` → `captcha` | 2 |

44064 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = ecom_auth`. `customer_id` permite cruzar con `alert_customers`, `ecom_account_logs` y `ai_gateway_logs`, sin ser FK de `users`. Correo, dispositivo e IP se conservan como observaciones del acceso; un cliente puede cambiar esos valores. No se crea un catálogo ficticio de clientes.

# ecom_account_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/ecom_account.jsonl` → `event_id` | 7661 |
| `customer_id` | `docs/04_logs/ecom_account.jsonl` → `customer_id` | 6235 |
| `event_type` | `docs/04_logs/ecom_account.jsonl` → `event` | 4 |
| `details_json` | `docs/04_logs/ecom_account.jsonl` → `details` | 6871 |
| `src_ip` | `docs/04_logs/ecom_account.jsonl` → `src_ip` | 6239 |
| `amount` | `docs/04_logs/ecom_account.jsonl` → `amount` | 5888 |

7661 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = ecom_account`. `customer_id` permite cruzar con clientes de alertas, autenticación e IA; no equivale a un usuario del directorio. `details_json` conserva los detalles variables de pedidos, tarjetas regalo y cambios de cuenta. `amount` es el importe observado cuando viene informado.

# ai_gateway_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/ai_gateway.jsonl` → `event_id` | 8817 |
| `session_id` | `docs/04_logs/ai_gateway.jsonl` → `session_id` | 8815 |
| `customer_id` | `docs/04_logs/ai_gateway.jsonl` → `customer_id` | 7112 |
| `authenticated` | `docs/04_logs/ai_gateway.jsonl` → `authenticated` | 1 |
| `src_ip` | `docs/04_logs/ai_gateway.jsonl` → `src_ip` | 7111 |
| `prompt` | `docs/04_logs/ai_gateway.jsonl` → `prompt` | 15 |
| `response_summary` | `docs/04_logs/ai_gateway.jsonl` → `response_summary` | 11 |
| `guardrail_triggered` | `docs/04_logs/ai_gateway.jsonl` → `guardrail.triggered` | 2 |
| `guardrail_category` | `docs/04_logs/ai_gateway.jsonl` → `guardrail.category` | 2 |
| `guardrail_action` | `docs/04_logs/ai_gateway.jsonl` → `guardrail.action` | 3 |
| `model` | `docs/04_logs/ai_gateway.jsonl` → `model` | 1 |
| `tokens_in` | `docs/04_logs/ai_gateway.jsonl` → `tokens_in` | 1199 |
| `tokens_out` | `docs/04_logs/ai_gateway.jsonl` → `tokens_out` | 262 |

8817 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = ai_gateway`. `session_id` permite cruzar con `alert_ai_sessions`: las dos sesiones citadas en alertas existen; la sesión no es única por evento. `customer_id` enlaza observaciones del mismo cliente en e-commerce, sin FK de `users`. El objeto fijo `guardrail` se descompone en tres columnas. Las llamadas a herramientas van en `ai_tool_calls`; no se duplican como JSON en esta tabla.

# ai_tool_calls

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/ai_gateway.jsonl` → `event_id` de la llamada | 7222 |
| `position` | Índice desde 0 de la llamada en `tool_calls[]` | 1 |
| `name` | `docs/04_logs/ai_gateway.jsonl` → `tool_calls[].name` | 4 |
| `arguments_json` | `docs/04_logs/ai_gateway.jsonl` → objeto `tool_calls[].args` | 2227 |
| `result` | `docs/04_logs/ai_gateway.jsonl` → `tool_calls[].result` | 2 |

7222 llamadas. Clave compuesta: (`event_id`, `position`); `event_id` → `ai_gateway_logs.event_id`. Los argumentos varían por herramienta y se conservan como JSON. Todos los resultados actuales son texto. Las posiciones permiten conservar varias llamadas por evento aunque la muestra actual tenga una.

# cloudtrail_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/cloudtrail.jsonl` → `event_id` | 6496 |
| `event_name` | `docs/04_logs/cloudtrail.jsonl` → `eventName` | 15 |
| `event_source` | `docs/04_logs/cloudtrail.jsonl` → `eventSource` | 3 |
| `aws_region` | `docs/04_logs/cloudtrail.jsonl` → `awsRegion` | 1 |
| `src_ip` | `docs/04_logs/cloudtrail.jsonl` → `sourceIPAddress` | 4 |
| `user_agent` | `docs/04_logs/cloudtrail.jsonl` → `userAgent` | 6 |
| `identity_type` | `docs/04_logs/cloudtrail.jsonl` → `userIdentity.type` | 1 |
| `identity_name` | `docs/04_logs/cloudtrail.jsonl` → `userIdentity.userName` | 5 |
| `access_key_id` | `docs/04_logs/cloudtrail.jsonl` → `userIdentity.accessKeyId` | 5 |
| `request_parameters_json` | `docs/04_logs/cloudtrail.jsonl` → `requestParameters` | 1406 |
| `error_code` | `docs/04_logs/cloudtrail.jsonl` → `errorCode` | 0 |
| `bytes_transferred` | `docs/04_logs/cloudtrail.jsonl` → `bytes_transferred` | 81 |

6496 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = cloudtrail`. El objeto fijo `userIdentity` se descompone sin duplicarlo. Identidad y clave son valores cloud observados; no se atribuyen automáticamente a `users`. `request_parameters_json` conserva los parámetros variables, incluidos buckets, objetos, usuarios afectados y políticas. Coincidencias con `alert_cloud` por identidad o clave y por los parámetros correspondientes, sin FK obligatoria. `error_code` está vacío en todos los eventos actuales (0 valores informados).

# cicd_builds_logs

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `event_id` | `docs/04_logs/cicd_builds.jsonl` → `event_id` | 559 |
| `pipeline` | `docs/04_logs/cicd_builds.jsonl` → `pipeline` | 4 |
| `build_id` | `docs/04_logs/cicd_builds.jsonl` → `build_id` | 276 |
| `runner_asset_id` | `docs/04_logs/cicd_builds.jsonl` → `runner`; cruce con `activos.csv.hostname` → `asset_id` | 1 |
| `step` | `docs/04_logs/cicd_builds.jsonl` → `step` | 8 |
| `status` | `docs/04_logs/cicd_builds.jsonl` → `status` | 2 |
| `details_json` | `docs/04_logs/cicd_builds.jsonl` → `details` | 238 |

559 registros. `event_id` es clave primaria y referencia a `logs.event_id`, con `source = cicd_builds`. `runner_asset_id` → `assets.asset_id`: todos los runners se identifican. `build_id` agrupa pasos y no es único por evento. `details_json` conserva autor declarado, commit, paquetes, red y salida cuando aparecen; el autor no se considera automáticamente el usuario autenticado que ejecutó el build.

# alert_history

| Atributos | Origen | Cantidad de valores únicos |
|---|---|---:|
| `alert_id` | Alerta clasificada → `alerts.alert_id` | Pendiente de triaje |
| `verdict` | Resultado del triaje: `true_positive`, `false_positive` o `benign_true_positive`; dominio en `docs/01_contexto/politica_soc.md`, apartado 1 | 3 permitidos |

Atributos aprobados: `alert_id` es clave primaria y referencia a `alerts.alert_id`. Cada alerta tiene 0..1 clasificación guardada; cada clasificación pertenece a una alerta. No conserva varias evaluaciones de la misma alerta.

`verdict` es obligatorio y solo admite `true_positive`, `false_positive` o `benign_true_positive`. Esta tabla se alimentará con resultados del triaje, no con clasificaciones preexistentes en los CSV/JSONL. Los tres valores son el dominio permitido, no un recuento de resultados ya generados.

# severity_assessments

Histórico de evaluaciones de severidad generado durante el triaje. `assessment_id` es la clave primaria; `alert_id` referencia `alerts.alert_id`. Una alerta puede tener varias evaluaciones. Se conservan severidad original, criticidad considerada, base de matriz, ajuste, severidad final, veredicto, método, justificación, versión de reglas, huella de política, copia de entradas, intervalo de observación y fecha de evaluación.

El esquema reside en `src/database/pipeline.sql`; no procede de nuevas filas inventadas en los CSV originales. Las evaluaciones se añaden con nuevos triajes válidos. [Campos y reglas de persistencia](severity_audit.md).

# severity_evidence

Evidencias de una evaluación: `evidence_id` es la clave primaria y `assessment_id` referencia `severity_assessments.assessment_id`. Cada fila identifica condición, estado, fuente, clave, referencia, hallazgo y valores observados. Puede referenciar `logs.event_id`, `changes.change_id`, `assets.asset_id` y `business_services.service_id`.

Los estados distinguen condiciones confirmadas, refutadas, desconocidas y no evaluadas. Los vínculos a cambios identifican referencias de contexto; no son por sí solos una prueba completa de autorización. [Detalle del modelo](severity_audit.md).

