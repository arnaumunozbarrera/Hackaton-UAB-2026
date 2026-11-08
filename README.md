# Tarvia SOC · Hackathon UAB 2026

**Triaje de alertas de ciberseguridad con IA, evidencias trazables y revisión del analista.**

Proyecto para el reto Deloitte Cyber AI: ayudar al SOC de Tarvia, un retailer ficticio, a convertir una cola de alertas en decisiones argumentadas. Trabajamos sobre el dataset del reto: **11.061 alertas y 814.471 eventos de log**, junto con inventario, identidades, cambios autorizados e inteligencia de amenazas.

El problema no es solo detectar actividad sospechosa: hay que distinguirla del ruido y de la actividad legítima, valorar su impacto en el negocio y justificar qué se cierra y qué se escala. Tarvia SOC reúne esas evidencias, automatiza los casos explicables mediante reglas y reserva el LLM para los que requieren investigación.

## Cómo funciona

![Diagrama del flujo de Tarvia SOC](docs/Diagrama.svg)

[Abrir el diagrama a tamaño completo](docs/Diagrama.svg).

1. **Reunir el contexto.** La ingesta desde los datos del reto o la API SOC simulada alimenta una base SQLite con alertas, logs, activos, usuarios e inteligencia.
2. **Reducir el ruido.** El filtro identifica duplicados y eventos explicados por contexto. El discriminador genera tickets sin LLM para los casos cubiertos por sus reglas; las alertas de severidad alta o crítica y las de entornos OT pasan al LLM.
3. **Investigar con IA.** El modelo recibe el contexto, el runbook y alertas similares ya resueltas. Si necesita más evidencias, solicita consultas de un catálogo sobre la base en solo lectura y entrega un ticket estructurado con veredicto, evidencias y recomendación.
4. **Aplicar la política y validar.** El código calcula la severidad según la matriz del SOC y la criticidad del activo, aplica reglas de escalado y comprueba el formato y las restricciones del ticket.
5. **Decidir y profundizar.** El panel permite revisar consultas, evidencias y decisiones, aprobar o escalar y consultar el histórico. Para alertas escaladas, el módulo de investigación reconstruye la cadena de ataque, su origen y alcance a lo largo de varios días.

La respuesta se integra con la **API simulada**: las acciones permitidas a N1 por la política pueden automatizarse; las que requieren autorización se ejecutan tras la aprobación del operador. El LLM consulta evidencias y propone acciones; la aplicación controla su ejecución.

## Por qué esta arquitectura

| Decisión | Motivo y compromiso |
|---|---|
| **SQLite como base común de evidencias** | Permite cruzar fuentes, conservar sus relaciones y reproducir las consultas sin desplegar servicios adicionales. Es una elección práctica para una demo local; no hemos validado su escalabilidad para un SOC en producción. |
| **Filtrado y resolución determinista antes del LLM** | Evita dedicar llamadas y contexto a duplicados o actividad explicada por fuentes oficiales. Las reglas dejan referencias y mantienen los casos de mayor riesgo en la ruta de investigación. El ahorro efectivo y la precisión requieren evaluación. |
| **LLM con lectura acotada y salida validada** | El modelo puede ampliar su investigación sin recibir acceso libre a SQL ni a herramientas de ejecución. Las consultas quedan registradas y las reglas de severidad y autorización se aplican en código, para que el criterio del modelo se pueda revisar frente a evidencias y política. |

## Demo y resultados

[Ver el vídeo de demostración](docs/VideoDemo.mp4).

La demo ofrece una vista general de la web y recorre un caso concreto para explicar cómo trabaja el analista:

- **Panel operativo:** cola de alertas priorizada, indicadores de actividad, plazos SLA, estado del pipeline y registro de acciones automáticas.
- **Detalle e investigación:** veredicto, severidad, evidencias, consultas de la IA y reconstrucción de la cadena de ataque, con su cronología, alcance y preguntas abiertas.
- **Revisión del analista:** recomendaciones, acciones que requieren aprobación y controles para aprobar, rechazar, escalar o solicitar más información.
- **Histórico de decisiones:** registro de resoluciones humanas y automáticas, con su justificación y las evidencias que las respaldan.

El recorrido muestra cómo se conectan la investigación con IA, las reglas de la política SOC y la intervención humana en una misma interfaz. La evaluación de precisión, coste y latencia queda pendiente.

## Puesta en marcha

Requisitos: **Python 3.10+ y Git**. Ejecutar desde la raíz del repositorio.

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

Preparar la base, procesar un lote y abrir el panel con respuestas simuladas:

```bash
python -m src.database.build
python -m src.database.enrich
python -m src.main --no-sync --limit 50 --mode mock
python -m src.llm_triage serve --mock --detail-mode mock
```

Panel: <http://127.0.0.1:8765>. La carga genera `data/tarvia.sqlite` y un informe de ingesta; conserva las anomalías de origen y comprueba la integridad. Una base existente solo se sustituye con `--replace`, que también reconstruye el histórico.

Para usar **Claude real**, configurar `ANTHROPIC_API_KEY` en `.env` y ejecutar `python -m src.llm_triage serve --detail-mode anthropic`, o iniciar sesión en Claude Code y usar `python -m src.llm_triage serve --claude-code`. En lotes se selecciona con `--mode anthropic` o `--mode claude-code`. Los embeddings usan `BAAI/bge-m3`; la primera ejecución puede descargar el modelo. `TARVIA_EMBEDDING_BACKEND=hashing` permite usar un codificador determinista sin esa descarga.

Para simular la llegada periódica de alertas, arrancar `scripts/mock_api.ps1` o `bash scripts/mock_api.sh` en otra terminal y ejecutar:

```bash
python -m src.database.live
python -m src.llm_triage serve --mock --detail-mode mock --db data/tarvia_live.sqlite --live 10 --live-batch 3
```

La documentación de la API SOC simulada está en <http://127.0.0.1:8000/docs> mientras se ejecuta.

## Alcance y documentación

El proyecto incluye triaje, aplicación de política, investigación de cadenas de ataque y respuesta contra la API simulada. La demo muestra consultas y una reconstrucción con Claude Code; **queda pendiente una evaluación sistemática con una muestra etiquetada**, incluida la precisión del discriminador, el coste y la latencia. El asistente del panel filtra la cola en local; no es un chat conectado al LLM. El dataset es sintético y no demuestra rendimiento sobre un SOC real.

- [Contexto y datos del reto](docs/README.md): originales en `docs/`.
- [Diseño y trazabilidad de la base](implementation_docs/trazabilidad_bd.md): esquema y cargadores en `src/database/`.
- [Estado técnico y limitaciones](implementation_docs/estado_proyecto.md): detalle de los módulos implementados en `src/`.
- [Contribución y desarrollo](CONTRIBUTING.md): scripts en `scripts/` y pruebas en `tests/`.

Comprobaciones de desarrollo:

```bash
pytest
ruff check .
ruff format --check .
```
