# Diseño de la base de datos

[trazabilidad_bd.md](trazabilidad_bd.md) recoge las tablas acordadas, sus atributos, fuentes, cantidades de valores únicos y relaciones.

[Diagrama navegable](diagrams/nueva_bd.html) · [SVG completo](diagrams/nueva_bd.svg) · [Editable en draw.io](diagrams/nueva_bd.drawio).

CSV derivados para alimentar relaciones:

- [asset_services.csv](asset_services.csv): activos y servicios de negocio.
- [change_assets.csv](change_assets.csv): cambios y activos, con el papel del activo.
- [change_users.csv](change_users.csv): cambios y cuentas identificadas.
- [criticality_relations.csv](criticality_relations.csv): alias documentados de productos, aplicaciones y recursos para resolver activos y servicios; sin valores de criticidad.

[Entradas y consultas de criticidad](criticidad_matriz.md): relaciones consultadas, procedencia y comprobación de cobertura antes de aplicar la matriz.

[Evaluaciones y evidencias de severidad](severity_audit.md): tablas de histórico, campos, relaciones y registro de la justificación de cada cálculo.

Los datos originales permanecen en `docs/`. El [esquema SQL](../src/database/schema.sql) y los cargadores de `src/database/` implementan este diseño.

`python -m src.database.build` genera la base local `data/tarvia.sqlite` y el informe `data/tarvia.ingestion.json`, con recuentos, comprobaciones y huellas de las fuentes.
