# prompt_builder: prompt de triaje N1 para una alerta

Genera, para un `alert_id`, el paquete que se envía al LLM: mensaje de sistema, mensaje de usuario y esquema JSON de
salida (`ticket_salida.schema.json`). El LLM tiene **acceso de solo lectura a la base de datos**, así que el prompt
**identifica** (alerta, entidades, logs) y le da consultas parametrizadas para buscar el detalle; no copia los datos.

## Qué contiene el prompt

El prompt es **compacto**: identifica y apunta a funciones de lectura que devuelven solo las columnas relevantes.

| Parte | Contenido | Tamaño |
|---|---|---|
| `system` (igual para todas las alertas, se puede cachear) | rol, 8 reglas y la política compactada: ajustes, SLA, aprobaciones, escalado y agrupación | ~3,1 KB |
| `user` | alerta, evidencia entre `<datos_no_confiables>`, identificadores (valores de los parámetros), afectados, severidad base con la fila de la matriz, plan del runbook (Cn→funciones) y notas, logs informativos agrupados con sus ID comprimidos sin pérdida, logs apartados con su referencia | ~1,5 KB de media (máx. 2,1 KB) |
| `tool` | `solicitar_contexto(motivo, comprobacion?, consultas[1..5])`: respuesta de tipo 2, con el enum de consultas de la alerta y sus firmas | ~2,4 KB |
| `response_schema` | `ticket_salida.schema.json` para la salida estructurada (no va dentro del texto) | — |

Lo que el LLM lee bajo demanda en lugar de recibirlo pegado: el texto del runbook (`runbook_text`), el detalle
de cada log (`log_detail`: solo source, timestamp y detail), identidad, activo, indicador, cambios, duplicados,
incidentes y la actividad en la ventana (`user_activity`, `host_activity`, `ip_activity`...). Todas las consultas
seleccionan columnas concretas, nunca `SELECT *`. `PromptConfig(inline_runbook=True)` vuelve a pegar el runbook
si el modelo no tiene herramientas.

El catálogo (`schema.py`) está escrito para `src/database/schema.sql`: las consultas de logs de varias fuentes leen
la vista `LOG_VIEW` (UNION ALL generado desde la constante `LOG_PROJECTION`) y `log_detail` devuelve la fila de detalle
completa como JSON. Los parámetros son numerados (`?1`, `?2`...) para poder reutilizar un valor; el ejecutor
(`tools.execute`) solo acepta nombres del catálogo, comprueba el número de parámetros, los enlaza como mapeo
(`{"1": ...}`), limita a 50 filas y se usa con una conexión de solo lectura (`connect_read_only`).

## Personalización

- **Por runbook** (`runbooks.PROFILES`): enfoque, consultas por comprobación y notas obligatorias (por ejemplo,
  IBAN implica escalado y aviso a Tesorería, OT solo se escala, el prompt de Vela es dato no confiable).
- **Por esquema** (`SchemaMap`): sigue disponible para plantillas con nombres lógicos (`{dim_log.timestamp}`), pero el
  catálogo actual usa ya los nombres físicos de `schema.sql`. Los identificadores se validan y los valores van siempre
  como parámetros.
- **Por despliegue** (`PromptConfig`): empresa, idioma, ventana, máximo de logs, consultas sí o no, y plantillas de
  sistema y de usuario (`templates.py`, con `string.Template`).
- **Fuente de contexto** (`ContextSource`): `DatabaseContextSource` (`db_context.py`) para el flujo real, sobre la
  base de datos y con los logs informativos que deciden las comprobaciones básicas (`src.checks`): sin guardas, los
  eventos explicados sin texto libre se apartan con su referencia; con guardas, todos son informativos.
  `DatasetContextSource` (docs/ + `log_noise_discard`) se mantiene para el chat temporal y los experimentos.
- **Runbooks**: `PromptBuilder(source, runbooks=runbooks_from_db(conn))` los lee de la tabla `runbooks`; la política y
  el esquema del ticket se siguen leyendo de `docs/` (solo lectura).

## Uso

```python
from src.prompt_builder import DatasetContextSource, PromptBuilder, PromptConfig

builder = PromptBuilder(DatasetContextSource("docs"), PromptConfig(max_logs=40))
package = builder.build("ALR-20261005-000172")
messages = package.to_messages()      # [{"role": "system", ...}, {"role": "user", ...}]
schema = package.response_schema      # para la salida estructurada del LLM
tool = package.tool                   # definición de solicitar_contexto (respuesta de tipo 2)

# flujo real, sobre la base de datos:
from src.prompt_builder import DatabaseContextSource, runbooks_from_db
source = DatabaseContextSource("data/tarvia.sqlite")
builder = PromptBuilder(source, runbooks=runbooks_from_db(source.conn))
```

```bash
python -m src.prompt_builder ALR-20261005-000172                    # prompt legible
python -m src.prompt_builder ALR-20261005-000172 --format messages  # JSON listo para la API
python -m src.prompt_builder ALR-20261005-000017 ALR-20261005-000136 --format json --out prompts.json
```

## Tests

```bash
pip install pytest
python -m pytest tests/test_prompt_builder.py -q
```

Hay 12 tests. Las pruebas unitarias usan un contexto falso: render y remapeo del esquema, rechazo de identificadores
inseguros, que cada consulta tenga tantos `?` como parámetros, el parser de runbooks y la neutralización de un cierre
`</datos_no_confiables>` inyectado. Las pruebas sobre `docs/` cubren la matriz, que cada runbook tenga perfil con
consultas válidas, el tamaño del prompt (que no lleve SQL, esquema ni texto del runbook), la compresión exacta de IDs, que el
ejecutor rechace consultas desconocidas o con parámetros incorrectos, y el recorrido completo con una alerta WAF real. Las que necesitan `docs/` se saltan si no existe.
