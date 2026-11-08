# log_noise_discard: selección de logs informativos

Paquete que, a partir de las alertas del SIEM, devuelve solo los logs que aportan información para decidir y
priorizar cada alerta. **No borra ni modifica ningún dato**: `docs/` se lee en modo solo lectura y el resultado es
una selección (`FilterResult`), con el motivo por el que se ha apartado cada log.

```python
from src.log_noise_discard import run_filter

result = run_filter("docs")
logs = result.kept_for_alert("ALR-20261005-000172")   # logs informativos de una alerta
motivo = result.discarded.get("WAF-0001840")           # etapa que lo apartó (N1/N2/N3/N4)
contexto = result.explanations.get("FW-0012345")       # N4: cambio, regla o fuente que lo explica
```

```bash
python -m src.log_noise_discard --data docs [--stages N1,N2,N3,N4] [--out salida.jsonl] [--stats-out stats.json]
```

## 1. Criterio por etapa

Las etapas se aplican en orden; cada una trabaja sobre lo que deja la anterior.

| Etapa | Un log se considera no informativo si... | Por qué |
|---|---|---|
| N0 | no aparece en el `related_events` de ninguna alerta | el triaje parte de las alertas; lo no citado queda fuera de alcance |
| N1 | la misma alerta ya cita otro log de la misma fuente con la misma plantilla y la misma entidad | repite la misma evidencia (beaconing, credential stuffing) |
| N2 | el mismo `event_id` lo citan dos o más alertas | no permite distinguir entre esas alertas |
| N3 | su contenido aparece en al menos el 80 % de las alertas de una regla (reglas con 5 o más alertas) y su entidad ya está en la alerta; se conserva un log de muestra por patrón; nunca en reglas high/critical ni OT | todas las alertas lo tienen, así que no ayuda a priorizar; se guardan los valores variables (`prompt`) |
| N4 | su actividad está explicada por una fuente de contexto oficial y el runbook la da por cerrable, **no tiene campos de texto libre** y no lo bloquea ninguna guarda | el log solo repite lo que ya dice el contexto; basta con citar la referencia (p. ej. `CHG-2026-1042`) |

**Plantilla:** el log sin los campos que cambian en cada evento (`event_id`, `timestamp`, pid, puertos, bytes,
sesión), con números y hashes de las URI sustituidos por marcadores. Está definida en `templates.py`.

### N4 en detalle

| Sub | Fuente de contexto | Condición (deben cumplirse todas) |
|---|---|---|
| A | `calendario_cambios.csv` (hora de Madrid convertida a UTC) | ventana del cambio y origen, destino o actor dentro de su alcance: escaneo de NESSUS01, pentest 192.0.2.10 a .12, PsExec en los hosts del cambio, mantenimiento OT desde JUMP01, Logisoft, Backup Operators, actualización del EDR, SCCM, FLUJO-0007 |
| B | `empresa_tarvia.md` | ENG-WS01 o WMS01 hacia OT; Logisoft de lunes a viernes de 8 a 18 h; `adm.*` desde JUMP01 |
| C | `geoip_asn.csv` y `ti_feed.jsonl` | escáner de Internet bloqueado cuya IP nunca obtuvo un 2xx ni un login correcto (RB-05); agente de impresoras o de monitorización; dominio benigno del TIP, excluyendo los de doble uso (RB-09) |
| D | `sandbox_informes.jsonl` | veredicto `clean` y detección bloqueada o en cuarentena (RB-02) |
| E | DLP | `matches` vacío, acción `audit` y el usuario no tiene baja comunicada (RB-04) |
| F | GeoIP, IdP y `eventos_rrhh.csv` | viaje imposible con un tramo por Microsoft Private Relay desde un dispositivo ya conocido del usuario, o viaje notificado en esas fechas (RB-03) |

**Excepciones: el log se conserva como informativo aunque esté explicado**

- **Texto libre.** Tiene algún campo abierto no vacío: asunto de correo, nombre de fichero, `command_line`,
  descripción, comando decodificado, motivo, `prompt`, nombre de regla, mensaje, `stdout`. Lo puede haber escrito
  el atacante y conviene que lo revise el triaje. La lista es configurable en `config.OPEN_TEXT_FIELDS`.
- **G1.** Contiene un indicador malicioso o sospechoso del TIP.
- **G2.** Su entidad tiene, en ±24 h, una alerta high o critical sin explicar, porque podría formar parte de una
  cadena de ataque.

Gracias a estas condiciones, N4 **no** descarta lo que solo parece autorizado: PsExec de `adm.aortega` en FS01
a las 00:40, alta en Domain Admins desde PRINT01 de madrugada, parada del EDR en PRINT01 fuera de la ventana,
Logisoft en domingo, o una subida a wetransfer de un usuario con baja comunicada.

## 2. Resultados (dataset completo)

| Etapa | Descartados | % del total | % sobre lo que entra en la etapa | Eventos restantes | Tamaño restante |
|---|---:|---:|---:|---:|---:|
| Total | — | — | — | 814.471 | 267,64 MB |
| N0 | 798.821 | 98,079 % | 98,08 % | 15.650 | 6,38 MB |
| N1 | 2.733 | 0,336 % | 17,46 % | 12.917 | 5,79 MB |
| N2 | 11 | 0,001 % | 0,09 % | 12.906 | 5,78 MB |
| N3 | 1.760 | 0,216 % | 13,64 % | 11.146 | 4,49 MB |
| N4 | 6.000 | 0,737 % | 53,83 % | **5.146** | **2,10 MB** |

### Agrupación

| Grupo | Etapas | Descartados | % del total | % sobre lo que entra en el grupo | MB descartados | % del tamaño total |
|---|---|---:|---:|---:|---:|---:|
| Fuera de alcance | N0 | 798.821 | 98,08 % | 98,08 % | 261,25 | 97,61 % |
| Redundancia | N1 + N2 + N3 | 4.504 | 0,55 % | 28,78 % | 1,90 | 0,71 % |
| Explicado por contexto | N4 | 6.000 | 0,74 % | 53,83 % | 2,39 | 0,89 % |
| **Informativo (resultado)** | — | **5.146** | **0,63 %** | — | **2,10** | **0,78 %** |

Cómo leer la agrupación:
- **% del total** compara siempre con los 814.471 eventos del dataset.
- **% sobre lo que entra en el grupo** compara con lo que quedaba al llegar al grupo: 814.471, 15.650 y 11.146
  eventos respectivamente.

Lectura: N0 elimina casi todo el volumen, pero entre los logs que las alertas citan de verdad (15.650), los grupos
Redundancia y Explicado por contexto apartan otro 67,1 %. Queda **un 32,9 % de los logs citados** (5.146), que
es lo que el triaje necesita ver.

### Desglose de N4

| Sub | Descartados | Conservados por texto libre | Detalle |
|---|---:|---:|---|
| A Cambio aprobado | 104 | 10 | 80 del escaneo de NESSUS01 (CHG-1049 a 1052), 20 del pentest (CHG-1042) y 4 de otros cambios. Conservados: SCCM (1), PsExec (4) y actualización del EDR (3), por tener `command_line` o `reason`; nóminas FLUJO-0007 (2), por tener nombre de fichero |
| B Regla de la empresa | 9 | 0 | ENG-WS01 hacia OT |
| C IP o dominio conocido | 4.123 | 0 | escáneres de Internet bloqueados (3.386), dominios benignos del TIP (464), agentes según la GeoIP (273) |
| D Sandbox | 59 | 0 | EICAR |
| E DLP sin datos sensibles | 0 | 57 | todos tienen nombre de fichero, que es texto libre |
| F Viaje o dispositivo | 1.705 | 0 | Private Relay con dispositivo conocido (1.704) y viaje notificado (1) |
| **Total** | **6.000** | **67** | además, 124 conservados por la guarda G2 |

## 3. Qué queda y limitaciones

- **Informativo final (5.146):** correos reportados (2.295), DNS de túnel o DGA (967), UC-EDR-001 (536),
  password spraying (381), detecciones de antivirus sin sandbox (352), beaconing hacia ISPs residenciales (172),
  credential stuffing (99), viajes imposibles sin explicación (94) y casos sueltos de alta señal.
- **Candidatos que no se han aplicado** (unos 2.376): remitentes habituales sin clic, SAP GUI lanzado desde Excel,
  detecciones en cuarentena sin sandbox, consultas DNSBL a spamhaus y Terraform desde CI-RUNNER01. Encajan con un
  runbook, pero ninguna fuente oficial los cubre.
- **N4 depende de la calidad del contexto.** Por eso exige que coincidan la ventana, el alcance y el actor. Los
  cambios se identifican por el contenido del calendario (IPs, hosts, reglas, destinatarios), no por fechas
  escritas en el código.
- El resultado es reproducible (siempre el mismo orden) y solo usa la biblioteca estándar
  (`zoneinfo`; en Windows necesita `tzdata`, que ya está en `requirements.txt`).
