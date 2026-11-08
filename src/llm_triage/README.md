# llm_triage: conexión con Anthropic, validación del ticket y chat temporal

Cierra el ciclo **prompt → LLM → ticket validado** sin depender todavía de la base de datos.

```
PromptBuilder.build(alert_id) ──► system + user + herramienta consultar_bd + esquema del ticket
        │
        ▼
TriageRunner.run()  ── Messages API (Anthropic) ──►  el LLM llama a consultar_bd(consulta, parametros)
        │                                              └─ DatasetToolBackend responde desde docs/ (luego, la BD)
        │                                           el LLM entrega el ticket llamando a emitir_ticket
        ▼
validate_ticket()  esquema (Draft 2020-12) + reglas de política → si falla, se devuelve el error al LLM (máx. 2 correcciones)
        ▼
TriageResult: ticket, valid, errors, attempts, transcript (consultas hechas), usage (tokens), elapsed_s
```

## Formato siempre igual
- El ticket solo puede llegar como entrada de la herramienta `emitir_ticket`, cuyo `input_schema` es
  `ticket_salida.schema.json`.
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

- Las dos herramientas (`consultar_bd` y `emitir_ticket`) corren dentro del proceso como servidor MCP del SDK, con el
  mismo backend y el mismo validador que el modo API.
- `tools=[]` quita las herramientas integradas de Claude Code (Bash, Read, Web...) y `setting_sources=[]` ignora
  `CLAUDE.md` y tu configuración: el agente solo puede leer con `consultar_bd`.
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
Son 15 tests y no usan la red: validación (válido y 6 tipos de error), backend, petición con caché, modo mock, un
modelo simulado que entrega un ticket inválido y lo corrige, el abandono tras el máximo de correcciones, y los manejadores y opciones del modo Claude Code.
