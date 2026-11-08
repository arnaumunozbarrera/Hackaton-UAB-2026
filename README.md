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

Validación del código y de la base cargada:

```bash
pytest
ruff check .
ruff format --check .
```
