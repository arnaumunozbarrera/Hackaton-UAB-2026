# Diagrama de la nueva base de datos

Generado desde `../trazabilidad_bd.md`: **56 tablas y 382 atributos**, incluida `alert_history`. No incluye tablas ni datos de la implementación retirada.

- [Visor navegable](nueva_bd.html): búsqueda por tabla, atributo o fuente; vistas por bloques, zoom y detalle de cada relación. Funciona sin conexión.
- [Diagrama completo SVG](nueva_bd.svg): todos los atributos y sus orígenes.
- [Archivo editable en draw.io / diagrams.net](nueva_bd.drawio): tablas, atributos y conexiones editables. Los cruces opcionales están en una capa desactivada inicialmente.
- [Mapa general](mapa_general.png): organización de las tablas, sin desplegar atributos.
- `context.svg`, `intelligence.svg`, `alerts.svg` y `logs.svg`: vistas por bloque; las referencias a otros bloques aparecen resumidas.
- `model.json`: definición estructurada de las tablas, atributos y relaciones representados.

**Continuas:** claves foráneas; la flecha apunta a la tabla referenciada. **Discontinuas:** coincidencias opcionales por valor (IP, hash, cliente, sesión, etc.); no son claves foráneas ni exigen correspondencia. El visor permite mostrarlas u ocultarlas.

PK = clave primaria; FK = clave foránea; UK = identificador único indicado en el diseño. Las claves compuestas están marcadas en todos sus atributos. La referencia compuesta de `email_attachment_contents` se detalla en el panel de relaciones del visor.

Los orígenes completos se muestran en el panel de atributos del visor. En los diagramas, los prefijos `01/` a `05/` abrevian las carpetas `docs/01_contexto/`, `docs/02_inventario/`, `docs/03_alertas/`, `docs/04_logs/` y `docs/05_inteligencia/`. Se indican CSV, JSONL y documentos reales; los Excel de consulta no se presentan como fuentes nuevas.

El diseño está implementado en [src/database/schema.sql](../../src/database/schema.sql). N → 1 resume una referencia de muchos registros a uno; las referencias opcionales se aclaran en las notas de la tabla y de la relación.
