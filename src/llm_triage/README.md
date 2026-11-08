# llm_triage: conexión con Anthropic, validación del ticket y chat temporal

Cierra el ciclo **prompt → LLM → ticket validado** sin depender todavía de la base de datos.

```
PromptBuilder.build(alert_id) ──► system + user + herramienta solicitar_contexto + esquema del ticket
        │
        ▼
TriageRunner.run()  ── Messages API (Anthropic) ──►  tipo 2: el LLM pide más datos con solicitar_contexto(motivo, consultas)
        │                                              └─ DatasetToolBackend responde desde docs/ (luego, la BD)
        │                                           tipo 1: el LLM entrega el ticket llamando a emitir_ticket
        ▼
apply_matrix_severity()  incorpora la severidad y su explicación calculadas en código
        ▼
validate_ticket()  esquema (Draft 2020-12) + reglas de política → si falla, se devuelve el error al LLM (máx. 2 correcciones)
        ▼
TriageResult: ticket, valid, errors, attempts, transcript (consultas hechas), usage (tokens), elapsed_s
```

## Dos tipos de respuesta del LLM
| Tipo | Herramienta | Cuándo | Qué ve el analista |
|---|---|---|---|
| 1. Veredicto | `emitir_ticket` | tiene contexto suficiente | la tarjeta del ticket, ya validado |
| 2. Ampliación de contexto | `solicitar_contexto(motivo, comprobacion?, consultas[1..5])` | la identificación del prompt no basta para decidir | un mensaje en el chat por cada ampliación: motivo, comprobación del runbook, consultas y filas leídas (solo lectura) |

Reglas del tipo 2 (`context_requests.py`):
- El motivo es obligatorio (mínimo 10 caracteres). Sin él, la petición se rechaza y el rechazo también se muestra.
- Entre 1 y 5 consultas del catálogo por petición, y como máximo 6 ampliaciones por alerta. Al alcanzar el límite, se pide
  al modelo que entregue el ticket con lo que tenga (`needs_more_info` y `open_questions` si falta algo).
- Los errores de una consulta concreta vuelven al modelo sin anular el resto de la petición.

## Formato siempre igual
- El ticket solo puede llegar como entrada de la herramienta `emitir_ticket`. Su esquema deriva de
  `ticket_salida.schema.json`, excluyendo `severity` y `severity_rationale`: esos campos los completa el sistema
  con el resultado de la matriz antes de validar. El modelo recibe la severidad como contexto para el escalado,
  pero no la calcula, ajusta ni justifica. Los adaptadores API y Claude Code aplican la misma regla.
- `validator.py` comprueba además: `alert_ids` incluye la alerta; aislar, deshabilitar, revocar, resetear o desactivar
  claves tienen `requires_approval=true`; sobre OT solo se escala; `executed_actions` está vacío; un true_positive
  high o critical se escala.
- Si el ticket no es válido, el error vuelve al modelo como `tool_result` con `is_error` para que lo corrija. Tras
  `max_repairs` intentos fallidos el resultado sale con `valid=false` y la lista de errores (nunca un formato distinto).

## Uso
```powershell
copy .env.example .env      # y rellena ANTHROPIC_API_KEY (opcional: TARVIA_LLM_MODEL)
pip install -r requirements.txt

python -m src.llm_triage serve            # chat en http://127.0.0.1:8765
python -m src.llm_triage serve --mock     # sin API key: respuesta simulada para probar el flujo
python -m src.llm_triage triage ALR-20261005-000136            # por consola, imprime el resultado
python -m src.llm_triage triage ALR-20261005-000136 --mock --note "céntrate en el dispositivo"
```

La página (`static/chat.html`) muestra a la izquierda el chat con el ticket (veredicto, severidad, evidencias,
acciones y estado de la validación). A la derecha hay pestañas: contexto (mensaje de usuario y metadatos), mensaje de
sistema, herramienta y SQL que ejecutará la BD, llamadas del LLM, esquema de salida, y uso con la validación.
Todo el contenido se pinta con `textContent`, porque los datos pueden contener texto del atacante.

## Sin API key: Claude Code con tu suscripción (`--claude-code`)
`ClaudeCodeRunner` usa el Claude Agent SDK, que lanza el CLI de Claude Code con **la sesión de tu plan** (Pro o Max).
Ese consumo sale de los límites de uso del plan, no de créditos de API. Es para uso personal y local.

- Las dos herramientas (`solicitar_contexto` y `emitir_ticket`) corren dentro del proceso como servidor MCP del SDK, con el
  mismo backend y el mismo validador que el modo API.
- `tools=[]` quita las herramientas integradas de Claude Code (Bash, Read, Web...) y `setting_sources=[]` ignora
  `CLAUDE.md` y tu configuración: el agente solo puede leer con `solicitar_contexto`.
- Al arrancar en este modo se **retira `ANTHROPIC_API_KEY` del proceso**: si estuviera definida, Claude Code
  facturaría por API en lugar de usar tu plan.

```powershell
pip install claude-agent-sdk             # incluye el CLI de Claude Code
claude                                   # una vez: /login con tu cuenta Max y /status para comprobarlo
python -m src.llm_triage serve --claude-code
python -m src.llm_triage triage ALR-20261005-000136 --claude-code --model sonnet
```

## Sin base de datos
`DatasetToolBackend` responde las mismas funciones del catálogo desde docs/ y devuelve filas parecidas a las que
devolverá la BD. Las consultas de actividad (`user_activity`, `ip_activity`...) recorren los logs con un prefiltro de
texto (de 1 a 5 s por llamada). `incident_links` no está disponible sin la correlación L2. Cuando exista la BD, basta
con pasar a `TriageRunner` un backend que use `prompt_builder.tools.execute` con `connect_read_only`.

## Tests
```powershell
python -m pytest tests/test_llm_triage.py -q
```
Son 17 tests y no usan la red: validación (válido y 6 tipos de error), backend, petición con caché, modo mock, un
modelo simulado que entrega un ticket inválido y lo corrige, el abandono tras el máximo de correcciones, los manejadores y opciones del modo Claude Code, las tareas en segundo plano y las reglas del tipo 2 (motivo, límite de consultas y de ampliaciones).
