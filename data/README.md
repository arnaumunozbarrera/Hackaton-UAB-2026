# Base SQLite local

- `tarvia.sqlite`: base creada y cargada con el modelo acordado.
- `tarvia.ingestion.json`: resultados de validación, recuentos por tabla y atributo, fuentes con SHA-256 y anomalías conservadas.

Se generan desde la raíz del proyecto con `python -m src.database.build` y no se versionan.
La base se construye en un archivo temporal; solo se publica cuando pasa la validación.
`alert_history` empieza vacía: las clasificaciones se incorporarán durante el triaje.

El informe conserva una inversión de fechas del feed de inteligencia; la carga no corrige datos por suposición.
Para reconstruir expresamente una base existente se necesita `--replace`, que también reinicia cualquier resultado almacenado.
