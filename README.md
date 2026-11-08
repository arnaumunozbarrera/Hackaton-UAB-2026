# Hackathon UAB 2026 · Tarvia SOC

Proyecto de triaje de alertas de ciberseguridad para el reto de Deloitte Cyber AI.
El contexto del reto y los datos originales están en [docs/README.md](docs/README.md).

El modelo de datos acordado está en [implementation_docs/trazabilidad_bd.md](implementation_docs/trazabilidad_bd.md).
El esquema SQLite está en [src/database/schema.sql](src/database/schema.sql) y la ingesta en `src/database/`.

## Estructura

- `docs/`: datos originales, contexto, política SOC y herramientas del reto. No modificar.
- `implementation_docs/`: diseño acordado y CSV derivados de relaciones.
- `src/database/`: esquema, carga y validación del modelo acordado; `sync.py` incorpora alertas nuevas de la API.
- `src/checks/`: comprobaciones básicas deterministas por alerta (cierre automático con ticket o paso al LLM).
- `src/prompt_builder/`, `src/llm_triage/`: prompt por alerta, catálogo de consultas de solo lectura y bucle LLM.
- `src/workflow/`, `src/main.py`: orquestación por alerta y almacenamiento de resultados (`triage_*`).
- `src/webapp/`, `frontend/`: interfaz del analista (veredicto, acciones, aprobaciones, historial).
- `src/dev/`, `dev/`: API simulada con el feed de depuración de 20 alertas.
- `data/`: base SQLite e informe de ingesta locales; no se versionan.
- `tests/`: pruebas de conversión, integridad e ingesta.
- `scripts/`: preparación del entorno y arranque de la API simulada.
- `.github/`: comprobaciones de formato, análisis estático y pruebas cuando existan.

## Entorno de desarrollo

Python 3.10+ y Git.

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
.\.venv\Scripts\Activate.ps1
```

Linux, macOS o Git Bash:

```bash
bash scripts/setup.sh
source .venv/bin/activate
```

API simulada: `scripts/mock_api.ps1` o `bash scripts/mock_api.sh`.
Su documentación está disponible en `http://127.0.0.1:8000/docs` al arrancarla.

Consulta [CONTRIBUTING.md](CONTRIBUTING.md) antes de contribuir.

## Crear y cargar la base de datos

```bash
python -m src.database.build
```

Genera `data/tarvia.sqlite` y `data/tarvia.ingestion.json`. También se puede usar
`scripts/create_db.ps1` o `bash scripts/create_db.sh`.

La carga utiliza los originales de `docs/` y los tres CSV derivados de `implementation_docs/`.
Crea 62 tablas, carga las 18 fuentes de logs y las alertas, y deja vacías `alert_history` y las seis tablas
de resultados del triaje (`triage_runs`, `triage_checks`, `triage_tickets`, `triage_context_requests`,
`analyst_decisions`, `executed_actions`).

Para el flujo de triaje la base se crea **solo con contexto** (inventario, inteligencia, reglas y runbooks;
sin alertas ni logs, que llegan por la API con cada alerta):

```bash
bash scripts/create_db.sh --context-only --replace
```
Antes de publicar la base comprueba las claves, la integridad, las cantidades de valores únicos del diseño
y que los archivos de entrada no hayan cambiado. Las anomalías de origen se conservan y figuran en el informe.

Una base existente no se sustituye salvo que se indique `--replace` de forma explícita.
Ese modo reconstruye también el histórico: no debe utilizarse para incorporar resultados de triaje.

## Flujo de triaje N1 (por alerta)

API simulada → ingesta de la alerta y sus logs → comprobaciones básicas (cierre automático con ticket, o se
mantiene) → prompt → LLM (`emitir_ticket` / `solicitar_contexto`, máx. 6 peticiones, validador con 2
reparaciones) → resultados en `triage_*` → el analista acepta o rechaza el veredicto y cada acción en la web;
la contención se ejecuta contra la API simulada con aprobación y nunca sobre OT. Detalle y estado de la
implementación: [implementation_docs/triage_workflow.md](implementation_docs/triage_workflow.md).

```bash
bash scripts/create_db.sh --context-only --replace     # base solo con contexto (una vez)
bash scripts/mock_api_dev.sh                           # API simulada con 20 alertas de depuración (:8000)
python -m src.main --llm claude-code                   # o anthropic | openai | mock | none; --limit N, --alert ID
python -m src.webapp                                   # interfaz del analista: http://127.0.0.1:8080
```

Variables de entorno (todas opcionales):

| Variable | Uso |
| --- | --- |
| `TARVIA_DB` | Base SQLite (por defecto `data/tarvia.sqlite`) |
| `TARVIA_SOC_API` | URL de la API simulada (por defecto `http://127.0.0.1:8000`) |
| `TARVIA_MOCK_ALERTS` | Feed de `mock_api_dev.sh`: fichero JSONL (por defecto `dev/alertas_debug.jsonl`) o `all` |
| `TARVIA_MOCK_LOGS` | Logs de `mock_api_dev.sh`: `dev/alertas_debug_events.jsonl` sirve solo los logs de las 20 alertas (arranque inmediato); sin definir, todo `docs/04_logs` |
| `TARVIA_CONTAINMENT_LOG` | Registro de contención de la API simulada (por defecto `data/containment_log.jsonl`) |
| `TARVIA_ANALYST` | Nombre del analista propuesto en la web |
| `ANTHROPIC_API_KEY`, `TARVIA_LLM_MODEL` | Solo para `--llm anthropic` (en `.env`, nunca versionado) |
| `TARVIA_OPENAI_BASE_URL`, `TARVIA_OPENAI_MODEL`, `TARVIA_OPENAI_API_KEY` | Solo para `--llm openai`: modelo del clúster con API compatible con OpenAI (`/v1/chat/completions`). La clave es opcional. No usa la configuración de Claude |

`--llm claude-code` usa el CLI de Claude Code con la sesión de tu plan (sin clave de API).
`--llm openai` llama a `TARVIA_OPENAI_BASE_URL/chat/completions` (vLLM, SGLang, Ollama, LiteLLM). El nombre del modelo es el que devuelve `GET {base}/models`.
El feed de depuración se regenera con `python scripts/make_debug_alerts.py`.

Validación del código y de la base cargada:

```bash
pytest
ruff check .
ruff format --check .
```
