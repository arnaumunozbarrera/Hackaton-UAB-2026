# Hackathon UAB 2026 · Tarvia SOC

Proyecto de triaje de alertas de ciberseguridad para el reto de Deloitte Cyber AI.
El contexto del reto y los datos originales están en [docs/README.md](docs/README.md).

El modelo de datos acordado está en [implementation_docs/trazabilidad_bd.md](implementation_docs/trazabilidad_bd.md).
El esquema SQLite está en [src/database/schema.sql](src/database/schema.sql) y la ingesta en `src/database/`.

## Estructura

- `docs/`: datos originales, contexto, política SOC y herramientas del reto. No modificar.
- `implementation_docs/`: diseño acordado y CSV derivados de relaciones.
- `src/database/`: esquema, carga y validación del modelo acordado.
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
Crea 56 tablas, carga las 18 fuentes de logs y las alertas, y deja `alert_history` vacía hasta el triaje.
Antes de publicar la base comprueba las claves, la integridad, las cantidades de valores únicos del diseño
y que los archivos de entrada no hayan cambiado. Las anomalías de origen se conservan y figuran en el informe.

Una base existente no se sustituye salvo que se indique `--replace` de forma explícita.
Ese modo reconstruye también el histórico: no debe utilizarse para incorporar resultados de triaje.

## Flujo completo de triaje

```
SOC API ─► database.sync ─► BD (schema.sql + enrich: vistas del catálogo, dim_log, pipeline.sql)
        ─► selección de logs (log_noise_discard, persistida en alert_log_selection)
        ─► discriminador (todo explicado por contexto → ticket determinista, sin LLM)
        ─► embeddings (alertas similares ya resueltas) ─► prompt_builder (DbContextSource)
        ─► LLM (solicitar_contexto sobre la BD en solo lectura) ─► validador ─► triage_tickets
        ─► front (cola por criticidad, decisión del operador) ─► alert_history
```

| Paso | Comando |
|---|---|
| Capa derivada (vistas, selección, embeddings; incremental) | `python -m src.database.enrich` |
| Triaje por lotes | `python -m src.main --no-sync --limit 50 [--mode mock\|anthropic\|claude-code]` |
| Front + API (cola, histórico, estadísticas, decisiones) | `python -m src.llm_triage serve --mock` → `http://127.0.0.1:8765` |
| Tiempo real: BD sin alertas + ingesta periódica desde la SOC API | `python -m src.database.live` y `python -m src.llm_triage serve --mock --db data/tarvia_live.sqlite --live 10 --live-batch 3` (con `scripts/mock_api.ps1` arrancado) |

Al abrir una alerta en el front se pide el criterio del LLM real (`--detail-mode`, por defecto `auto`: Claude Code si
`claude-agent-sdk` está instalado, si no la API de Anthropic con `ANTHROPIC_API_KEY`, si no mock). Los lotes y el modo
`--live` siguen usando el modo del servidor (`--mock` para no gastar tokens).

El chat de depuración del prompt sigue en `/chat`; `serve --dataset` mantiene el modo original sobre `docs/`.
El estado del proyecto está en [implementation_docs/estado_proyecto.md](implementation_docs/estado_proyecto.md).

Validación del código y de la base cargada:

```bash
pytest
ruff check .
ruff format --check .
```
