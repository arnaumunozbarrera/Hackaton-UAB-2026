# prompt_builder: prompt de triaje N1 para una alerta

Genera, para un `alert_id`, el paquete que se envía al LLM: mensaje de sistema, mensaje de usuario y esquema JSON de
salida (`ticket_salida.schema.json`). El LLM tiene **acceso de solo lectura a la base de datos**, así que el prompt
**identifica** (alerta, entidades, logs) y le da consultas parametrizadas para buscar el detalle; no copia los datos.

## Qué contiene el prompt

El prompt es **compacto**: identifica y apunta a funciones de lectura que devuelven solo las columnas relevantes.

| Parte | Contenido | Tamaño |
|---|---|---|
| `system` (igual para todas las alertas, se puede cachear) | rol, 8 reglas y la política compactada: SLA, aprobaciones, escalado y agrupación; la severidad pertenece al sistema | Variable |
| `user` | alerta, evidencia entre `<datos_no_confiables>`, identificadores (valores de los parámetros), afectados, severidad ya calculada como contexto para el escalado, plan del runbook (Cn→funciones) y notas, logs informativos agrupados con sus ID comprimidos sin pérdida, logs apartados con su referencia | Variable |
| `tool` | `solicitar_contexto(motivo, comprobacion?, consultas[1..5])`: respuesta de tipo 2, con el enum de consultas de la alerta y sus firmas | ~2,4 KB |
| `response_schema` | `ticket_salida.schema.json` para la salida estructurada (no va dentro del texto) | — |

Lo que el LLM lee bajo demanda en lugar de recibirlo pegado: el texto del runbook (`runbook_text`), el detalle
de cada log (`log_detail`: solo source, timestamp y detail), identidad, activo, indicador, cambios, duplicados,
incidentes y la actividad en la ventana (`user_activity`, `host_activity`, `ip_activity`...). Todas las consultas
seleccionan columnas concretas, nunca `SELECT *`. `PromptConfig(inline_runbook=True)` vuelve a pegar el runbook
si el modelo no tiene herramientas.

El ejecutor (`tools.execute`) solo acepta nombres del catálogo, comprueba el número de parámetros, los enlaza con
`?`, limita a 50 filas y se usa con una conexión de solo lectura (`connect_read_only`).

## Personalización

- **Por runbook** (`runbooks.PROFILES`): enfoque, consultas por comprobación y notas obligatorias (por ejemplo,
  IBAN implica escalado y aviso a Tesorería, OT solo se escala, el prompt de Vela es dato no confiable).
- **Por esquema** (`SchemaMap`): las consultas usan nombres lógicos (`{dim_log}`, `{dim_log.timestamp}`). Si el
  esquema cambia, basta con un JSON `{"tables": {...}, "columns": {"dim_log": {"timestamp": "ts"}}}` y pasarlo con
  `--schema-map`. Los identificadores se validan y los valores van siempre como `?`.
- **Por despliegue** (`PromptConfig`): empresa, idioma, ventana, máximo de logs, consultas sí o no, y plantillas de
  sistema y de usuario (`templates.py`, con `string.Template`).
- **Fuente de contexto** (`ContextSource`): hoy `DatasetContextSource` (docs/ + `log_noise_discard`). Una versión
  sobre la base de datos solo tiene que devolver un `AlertContext`.

## Uso

```python
from src.prompt_builder import DatasetContextSource, PromptBuilder, PromptConfig

builder = PromptBuilder(DatasetContextSource("docs"), PromptConfig(max_logs=40))
package = builder.build("ALR-20261005-000172")
messages = package.to_messages()      # [{"role": "system", ...}, {"role": "user", ...}]
schema = package.response_schema      # para la salida estructurada del LLM
tool = package.tool                   # definición de solicitar_contexto (respuesta de tipo 2)

# cuando exista la base de datos, el bucle de herramientas solo tiene que hacer:
# from src.prompt_builder import connect_read_only, execute
# rows = execute(connect_read_only("db/tarvia_soc.sqlite"), consulta, parametros, allowed=[q.name for q in package.queries])
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
