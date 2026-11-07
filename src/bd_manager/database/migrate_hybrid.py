"""
Tarvia SOC - migrate the main database (tarvia_soc.sqlite) to the hybrid schema (21 source tables).

Source layer (21 tables, delivered data + documentation, relations in columns + intact JSON records):
  usuario, activo, zona_red, tienda, servicio_negocio, activo_servicio, vulnerabilidad, evento_rrhh, cambio,
  archivo_fuente, documento, regla, alerta, alerta_evento, participacion, evento, ocurrencia_indicador,
  indicador, inteligencia, geoip, sandbox
System layer (values already computed by L2/L3/pipeline, preserved):
  resultado_alerta, fact_incident, bridge_alert_incident, fact_attack_step, dim_mitre, ref_severity_matrix (+ pipeline tables)
Compatibility views keep the previous names (fact_alert, dim_log, dim_user, dim_vulnerability, dim_context, dim_rule,
bridge_alert_entity, bridge_alert_event) so l2_correlate.py, l3_reconstruct.py and the pipeline keep working.

Usage: python migrate_hybrid.py --db tarvia_soc.sqlite --data ../docs --stage all|base|events|switch|finish
"""

import argparse
import csv
import hashlib
import ipaddress
import json
import pathlib
import re
import sqlite3
import time
import zlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")
SHA = re.compile(r"^[0-9a-fA-F]{64}$")


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def b(v):
    if v is None or v == "":
        return None
    return 1 if str(v).strip().lower() in ("true", "1", "yes", "sí", "si") else 0


def nuser(v):
    if not v or not isinstance(v, str):
        return None
    return v.strip().lower().split("\\")[-1].split("@")[0] or None


def is_ip(v):
    try:
        ipaddress.ip_address(str(v))
        return True
    except Exception:
        return False


def g(d, path):
    for p in path.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


_DYNAMIC_LOG_VALUE = re.compile(
    r"(?i)\b(?:[0-9a-f]{8}-[0-9a-f-]{27,}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?|\d{1,3}(?:\.\d{1,3}){3}|\d+)\b"
)


def normalize_log_text(value):
    """Return a stable message template with volatile IDs, timestamps and numbers masked."""
    if value is None:
        return ""
    text = str(value).strip().lower()
    text = _DYNAMIC_LOG_VALUE.sub("<dynamic>", text)
    return re.sub(r"\s+", " ", text)


def log_fingerprint(source, action=None, result=None, detail=None):
    """Build a reusable fingerprint without storing the complete log payload in the pattern catalog."""
    material = "|".join(
        (normalize_log_text(v) for v in (source, action, result, detail))
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def register_common_log_pattern(con, *, pattern_id, pattern_name, description, source_product=None,
                               action=None, result=None, message_template=None,
                               classification="candidate", filtering_action="retain",
                               confidence=None, rationale=None, enabled=1):
    """Register or update a reusable common/noise pattern; does not import or delete log data."""
    fingerprint = log_fingerprint(source_product, action, result, message_template)
    con.execute(
        """INSERT INTO common_log_pattern
        (pattern_id, pattern_name, description, source_product, action, result,
         normalized_fingerprint, message_template, classification, filtering_action,
         confidence, rationale, enabled, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(pattern_id) DO UPDATE SET
          pattern_name=excluded.pattern_name, description=excluded.description,
          source_product=excluded.source_product, action=excluded.action,
          result=excluded.result, normalized_fingerprint=excluded.normalized_fingerprint,
          message_template=excluded.message_template, classification=excluded.classification,
          filtering_action=excluded.filtering_action, confidence=excluded.confidence,
          rationale=excluded.rationale, enabled=excluded.enabled, updated_at=CURRENT_TIMESTAMP""",
        (pattern_id, pattern_name, description, source_product, action, result,
         fingerprint, message_template, classification, filtering_action,
         confidence, rationale, enabled),
    )


def match_log_event(con, event_id):
    """Match one already-loaded event against enabled patterns and record the decision."""
    event = con.execute(
        "SELECT event_id, fuente, accion, resultado, datos_json FROM evento WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    if event is None:
        raise ValueError(f"event not found: {event_id}")
    fingerprint = log_fingerprint(event[1], event[2], event[3], event[4])
    patterns = con.execute(
        """SELECT pattern_id, normalized_fingerprint, source_product, action, result
           FROM common_log_pattern WHERE enabled = 1"""
    )
    matches = []
    for pattern in patterns:
        pattern_fields = (pattern[2], pattern[3], pattern[4])
        has_fields = any(value is not None for value in pattern_fields)
        same_fields = has_fields and all(
            expected is None or normalize_log_text(expected) == normalize_log_text(actual)
            for expected, actual in ((pattern[2], event[1]), (pattern[3], event[2]), (pattern[4], event[3]))
        )
        if pattern[1] == fingerprint or same_fields:
            method = "fingerprint" if pattern[1] == fingerprint else "fields"
            matches.append((event_id, pattern[0], method, 1.0 if method == "fingerprint" else 0.8))
    con.executemany(
        """INSERT INTO log_pattern_match(event_id, pattern_id, matched_by, match_confidence)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(event_id, pattern_id) DO UPDATE SET
             matched_by=excluded.matched_by, match_confidence=excluded.match_confidence,
             matched_at=CURRENT_TIMESTAMP""",
        matches,
    )
    return len(matches)


DDL = r"""
-- ===================== INVENTARIO Y NEGOCIO =====================
CREATE TABLE zona_red (zona TEXT PRIMARY KEY, cidr TEXT, ubicacion TEXT, descripcion TEXT);
CREATE TABLE tienda (tienda TEXT PRIMARY KEY, nombre TEXT, ciudad TEXT, red TEXT);
CREATE TABLE servicio_negocio (servicio_id INTEGER PRIMARY KEY, nombre TEXT UNIQUE NOT NULL, criticidad TEXT,
  impacto TEXT, activos TEXT, responsable TEXT);
CREATE TABLE usuario (
  user_id TEXT PRIMARY KEY, user_key TEXT UNIQUE NOT NULL,          -- user_key = lower(username): join key used by logs
  username TEXT, upn TEXT UNIQUE, display_name TEXT, department TEXT, title TEXT, location TEXT,
  manager_id TEXT REFERENCES usuario(user_id), manager_upn TEXT,
  account_type TEXT, privileged INTEGER, vip INTEGER, mfa_method TEXT, status TEXT, created TEXT,
  workstation_asset_id TEXT REFERENCES activo(asset_id), workstation TEXT, notes TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);
CREATE TABLE activo (
  asset_id TEXT PRIMARY KEY, hostname TEXT UNIQUE NOT NULL, ip TEXT, ip_indicador_id INTEGER REFERENCES indicador(indicador_id),
  type TEXT, os TEXT, criticality TEXT, criticality_level INTEGER, zona TEXT REFERENCES zona_red(zona),
  tienda TEXT REFERENCES tienda(tienda), location TEXT, business_service TEXT,
  owner_user_id TEXT REFERENCES usuario(user_id), owner_upn TEXT, internet_facing INTEGER, edr_installed INTEGER, description TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);
CREATE TABLE activo_servicio (
  asset_id TEXT NOT NULL REFERENCES activo(asset_id), servicio_id INTEGER NOT NULL REFERENCES servicio_negocio(servicio_id),
  metodo TEXT,      -- activos.business_service | servicios_negocio.activos | ambos
  estado TEXT,      -- confirmado (two sources agree) | una_fuente
  PRIMARY KEY (asset_id, servicio_id));
CREATE TABLE vulnerabilidad (
  vulnerabilidad_id INTEGER PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES activo(asset_id), hostname TEXT,
  cve TEXT, producto TEXT, severidad_cvss TEXT, cvss_valor REAL, estado TEXT, detectada TEXT, notas TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);
CREATE TABLE evento_rrhh (
  rrhh_id INTEGER PRIMARY KEY, user_id TEXT REFERENCES usuario(user_id), usuario TEXT,
  fecha TEXT, tipo TEXT, detalle TEXT, fecha_efectiva TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);
CREATE TABLE cambio (
  cambio_id TEXT PRIMARY KEY, titulo TEXT, inicio TEXT, fin TEXT, solicitante TEXT,
  condiciones TEXT,  -- column "detalle" of calendario_cambios.csv
  alcance TEXT,      -- a time/scope match is evidence, not proof of authorisation
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);
-- ===================== DOCUMENTACION =====================
CREATE TABLE archivo_fuente (
  archivo_id INTEGER PRIMARY KEY, ruta TEXT UNIQUE NOT NULL, rol TEXT, formato TEXT, bytes INTEGER, sha256 TEXT,
  filas INTEGER, compresion TEXT, original BLOB NOT NULL);      -- original file, byte-identical after zlib.decompress
CREATE TABLE documento (
  archivo_id INTEGER PRIMARY KEY REFERENCES archivo_fuente(archivo_id), codigo TEXT UNIQUE NOT NULL, tipo TEXT,
  titulo TEXT, texto TEXT);
-- ===================== DETECCION Y RELACIONES =====================
CREATE TABLE regla (
  rule_id TEXT PRIMARY KEY, nombre TEXT, fuente TEXT, severidad_base TEXT, tactica TEXT, tecnica_id TEXT, tecnica TEXT,
  runbook TEXT REFERENCES documento(codigo), logica TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);
CREATE TABLE alerta (
  alert_id TEXT PRIMARY KEY, fecha TEXT NOT NULL, rule_id TEXT REFERENCES regla(rule_id), estado TEXT,
  source_product TEXT, rule_name TEXT, severidad TEXT, descripcion TEXT, tactica TEXT, tecnica_id TEXT, tecnica TEXT,
  runbook TEXT, archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER,
  datos_json TEXT NOT NULL);     -- complete original record (evidence + entities). No system results here.
CREATE TABLE alerta_evento (
  alert_id TEXT NOT NULL REFERENCES alerta(alert_id), posicion INTEGER NOT NULL,
  event_id TEXT NOT NULL REFERENCES evento(event_id), PRIMARY KEY (alert_id, posicion));
CREATE TABLE participacion (
  participacion_id INTEGER PRIMARY KEY,
  alert_id TEXT REFERENCES alerta(alert_id), event_id TEXT REFERENCES evento(event_id),
  tipo TEXT NOT NULL,            -- user host customer process cloud_identity bucket access_key ai_session session file
  rol TEXT, ambito TEXT,         -- ambito: interno externo cliente cloud desconocido
  valor_observado TEXT NOT NULL,
  user_id TEXT REFERENCES usuario(user_id), asset_id TEXT REFERENCES activo(asset_id),
  ruta TEXT, metodo TEXT, estado TEXT,       -- ruta = JSON path in the original record
  CHECK ((alert_id IS NULL) <> (event_id IS NULL)));
-- ===================== EVENTOS E INTELIGENCIA =====================
CREATE TABLE evento (
  event_id TEXT PRIMARY KEY, fuente TEXT NOT NULL, timestamp TEXT NOT NULL,       -- UTC
  accion TEXT, campo_accion TEXT, resultado TEXT, campo_resultado TEXT,            -- value + field of origin
  ip_origen TEXT, ip_origen_indicador_id INTEGER REFERENCES indicador(indicador_id),
  ip_destino TEXT, ip_destino_indicador_id INTEGER REFERENCES indicador(indicador_id),
  destino TEXT,                  -- generic destination (domain, URL, app, bucket, ip:port)
  user_key TEXT, customer_id TEXT, hostname TEXT, sha256 TEXT, ref_id TEXT,          -- resolved shortcuts (full detail in participacion)
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER,
  datos_json TEXT NOT NULL);     -- every field of the original record
CREATE TABLE common_log_pattern (
  pattern_id TEXT PRIMARY KEY,
  pattern_name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL,
  source_product TEXT,
  action TEXT,
  result TEXT,
  normalized_fingerprint TEXT,
  message_template TEXT,
  classification TEXT NOT NULL CHECK (classification IN ('noise', 'benign_expected', 'common_cross_product', 'candidate')),
  filtering_action TEXT NOT NULL DEFAULT 'retain' CHECK (filtering_action IN ('retain', 'aggregate', 'hide_from_triage')),
  confidence REAL CHECK (confidence BETWEEN 0 AND 1),
  rationale TEXT,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE log_pattern_match (
  event_id TEXT NOT NULL REFERENCES evento(event_id),
  pattern_id TEXT NOT NULL REFERENCES common_log_pattern(pattern_id),
  matched_by TEXT NOT NULL,              -- fingerprint | fields | analyst
  match_confidence REAL CHECK (match_confidence BETWEEN 0 AND 1),
  matched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (event_id, pattern_id)
);
CREATE TABLE indicador (
  indicador_id INTEGER PRIMARY KEY, tipo TEXT NOT NULL, valor TEXT NOT NULL, normalizado TEXT,
  UNIQUE (tipo, valor));
CREATE TABLE ocurrencia_indicador (
  ocurrencia_id INTEGER PRIMARY KEY, indicador_id INTEGER NOT NULL REFERENCES indicador(indicador_id),
  alert_id TEXT REFERENCES alerta(alert_id), event_id TEXT REFERENCES evento(event_id),
  sandbox_id INTEGER REFERENCES sandbox(indicador_id),
  rol TEXT, ruta TEXT,
  CHECK ((alert_id IS NOT NULL) + (event_id IS NOT NULL) + (sandbox_id IS NOT NULL) = 1));
CREATE TABLE inteligencia (
  indicador_id INTEGER PRIMARY KEY REFERENCES indicador(indicador_id), reputacion TEXT, confianza INTEGER,
  malware_family TEXT, tags TEXT, first_seen TEXT, last_seen TEXT, fuente TEXT, nota TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);
CREATE TABLE geoip (
  indicador_id INTEGER PRIMARY KEY REFERENCES indicador(indicador_id), pais TEXT, ciudad TEXT, asn TEXT, as_org TEXT,
  is_tor INTEGER, is_vpn_provider INTEGER, is_hosting INTEGER, is_residential_proxy INTEGER,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER);
CREATE TABLE sandbox (
  indicador_id INTEGER PRIMARY KEY REFERENCES indicador(indicador_id), md5 TEXT, file_name TEXT, veredicto TEXT, score INTEGER,
  malware_family TEXT, analysis_env TEXT, analyzed_at TEXT, nota TEXT,
  archivo_id INTEGER REFERENCES archivo_fuente(archivo_id), linea INTEGER,
  datos_json TEXT NOT NULL);     -- network, behaviours, dropped files, mitre
-- ===================== SYSTEM RESULTS (outside the 21 source tables) =====================
CREATE TABLE resultado_alerta (
  alert_id TEXT PRIMARY KEY REFERENCES alerta(alert_id),
  user_key TEXT REFERENCES usuario(user_key), hostname TEXT REFERENCES activo(hostname),
  context_key TEXT, event_id TEXT REFERENCES evento(event_id),   -- primary entities chosen by the system
  dedup_hash TEXT, verdict TEXT, final_severity TEXT, severity_rationale TEXT, confidence REAL, action TEXT,
  triaged_at TEXT, authorised_by TEXT);
"""

DOC_CODES = {
    "README.md": ("README", "contexto"),
    "01_contexto/empresa_tarvia.md": ("EMPRESA", "contexto"),
    "01_contexto/politica_soc.md": ("POLITICA_SOC", "politica"),
    "01_contexto/ticket_salida.schema.json": ("SCHEMA_TICKET", "esquema"),
    "01_contexto/informe_incidente.schema.json": ("SCHEMA_INFORME", "esquema"),
    "01_contexto/ticket_ejemplo.json": ("EJEMPLO_TICKET", "ejemplo"),
    "01_contexto/catalogo_casos_de_uso.csv": ("CATALOGO_CASOS_USO", "catalogo"),
    "06_herramientas/LEEME_herramientas.md": ("LEEME_HERRAMIENTAS", "herramienta"),
    "06_herramientas/mock_soc_api.py": ("MOCK_SOC_API", "herramienta"),
    "06_herramientas/refresh_iocs.py": ("REFRESH_IOCS", "herramienta"),
    "06_herramientas/requirements.txt": ("REQUIREMENTS", "herramienta"),
    "Reto IA en ciberseguridad.pptx": ("RETO_PRESENTACION", "presentacion"),
}
PROJECT_DOCS = [
    "db/README.md",
    "db/catalogo_bd.md",
    "db/schema.sql",
    "design/decision_sqlite_hibrido.png",
    "design/data_model_star_schema.png",
    "design/star_schema_alerts.png",
    "design/star_schema_v2_levels.png",
]
PROJECT_GLOBS = ["db/reports/*.json"]  # L3 incident reports


def role_of(rel):
    top = rel.split("/")[0]
    return {
        "01_contexto": "contexto",
        "02_inventario": "inventario",
        "03_alertas": "alertas",
        "04_logs": "logs",
        "05_inteligencia": "inteligencia",
        "06_herramientas": "herramientas",
    }.get(top, "documentacion")


def pptx_text(raw):
    import io
    import zipfile

    z = zipfile.ZipFile(io.BytesIO(raw))
    out = []
    slides = sorted(
        [n for n in z.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n)],
        key=lambda n: int(re.findall(r"\d+", n)[0]),
    )
    for n in slides:
        txt = " ".join(re.findall(r"<a:t>([^<]*)</a:t>", z.read(n).decode("utf-8", "ignore")))
        out.append(f"--- {n.split('/')[-1]} ---\n{txt}")
    return "\n".join(out)


class Idx:
    """indicator dictionary shared by all stages."""

    def __init__(s, con):
        s.con = con
        s.map = {r[1] + "|" + r[2]: r[0] for r in con.execute("SELECT indicador_id, tipo, valor FROM indicador")}
        s.next = (con.execute("SELECT MAX(indicador_id) FROM indicador").fetchone()[0] or 0) + 1
        s.new = []

    @staticmethod
    def norm(tipo, v):
        v = str(v).strip()
        if tipo in ("domain", "email", "sha256", "md5"):
            return v.lower(), v.lower()
        if tipo == "url":
            m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)([^/]*)(.*)$", v)
            return v, (m.group(1).lower() + m.group(2).lower() + m.group(3)) if m else v
        return v, v

    def get(s, tipo, v):
        if v is None or str(v).strip() == "":
            return None
        val, nor = s.norm(tipo, v)
        k = tipo + "|" + val
        if k not in s.map:
            s.map[k] = s.next
            s.new.append((s.next, tipo, val, nor))
            s.next += 1
        return s.map[k]

    def flush(s):
        if s.new:
            s.con.executemany("INSERT INTO indicador VALUES (?,?,?,?)", s.new)
            s.new = []


def ind_type(v):
    v = str(v)
    if is_ip(v):
        return "ip"
    if SHA.match(v):
        return "sha256"
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", v):
        return "url"
    if "@" in v and " " not in v:
        return "email"
    if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", v):
        return "domain"
    return None


# ---------------------------------------------------------------- STAGE 1: base
def stage_base(con, D):
    con.executescript(DDL)
    # ---- archivo_fuente + documento
    files = sorted([p for p in D.rglob("*") if p.is_file()])
    aid = {}
    for i, p in enumerate(files, 1):
        raw = p.read_bytes()
        rel = (
            str(p.relative_to(D)).replace("\\", "/")
            if D in p.parents
            else "proyecto/" + str(p.relative_to(ROOT)).replace("\\", "/")
        )
        fmt = p.suffix.lower().lstrip(".")
        filas = raw.count(b"\n") if fmt in ("jsonl", "csv") else None
        if fmt == "csv" and filas:
            filas -= 1
        con.execute(
            "INSERT INTO archivo_fuente VALUES (?,?,?,?,?,?,?,?,?)",
            (
                i,
                rel,
                "proyecto" if rel.startswith("proyecto/") else role_of(rel),
                fmt,
                len(raw),
                hashlib.sha256(raw).hexdigest(),
                filas,
                "zlib",
                zlib.compress(raw, 6),
            ),
        )
        aid[rel] = i
        code = None
        if rel in DOC_CODES:
            code, tipo = DOC_CODES[rel]
        elif re.match(r"01_contexto/runbooks/RB-\d+\.md$", rel):
            code, tipo = p.stem, "runbook"
        elif rel.startswith("proyecto/"):
            code, tipo = "PRJ_" + re.sub(r"\W+", "_", p.stem).upper(), ("diagrama" if fmt == "png" else "proyecto")
        if code:
            if fmt == "pptx":
                text = pptx_text(raw)
            elif fmt == "png":
                text = f"Diagrama del modelo de datos ({p.name}); imagen íntegra en archivo_fuente.original"
            else:
                text = raw.decode("utf-8", "replace")
            title = next(
                (l.lstrip("# ").strip() for l in text.splitlines() if l.strip() and not l.startswith("---")), p.name
            )[:200]
            con.execute("INSERT INTO documento VALUES (?,?,?,?,?)", (i, code, tipo, title, text))
    log(f"archivo_fuente {len(files)} | documento {con.execute('SELECT COUNT(*) FROM documento').fetchone()[0]}")

    def rows_csv(rel):
        with open(D / rel, encoding="utf-8", newline="") as f:
            for n, r in enumerate(csv.DictReader(f), 2):
                yield n, r

    idx = Idx(con)
    # ---- inventory
    con.executemany(
        "INSERT INTO zona_red VALUES (?,?,?,?)",
        [(r["zona"], r["cidr"], r["ubicacion"], r["descripcion"]) for _, r in rows_csv("02_inventario/zonas_red.csv")],
    )
    tiendas = [r for _, r in rows_csv("02_inventario/tiendas.csv")]
    con.executemany(
        "INSERT INTO tienda VALUES (?,?,?,?)", [(r["tienda"], r["nombre"], r["ciudad"], r["red"]) for r in tiendas]
    )
    svcs = [r for _, r in rows_csv("02_inventario/servicios_negocio.csv")]
    con.executemany(
        "INSERT INTO servicio_negocio VALUES (?,?,?,?,?,?)",
        [
            (i, r["servicio"], r["criticidad"], r["impacto"], r["activos"], r["responsable"])
            for i, r in enumerate(svcs, 1)
        ],
    )
    users = list(rows_csv("02_inventario/usuarios.csv"))
    assets = list(rows_csv("02_inventario/activos.csv"))
    upn2id = {r["upn"].lower(): r["user_id"] for _, r in users}
    host2id = {r["hostname"]: r["asset_id"] for _, r in assets}
    a_u, a_a = aid["02_inventario/usuarios.csv"], aid["02_inventario/activos.csv"]
    con.executemany(
        f"INSERT INTO usuario VALUES ({','.join('?'*21)})",
        [
            (
                r["user_id"],
                nuser(r["username"]),
                r["username"],
                r["upn"].lower(),
                r["display_name"],
                r["department"],
                r["title"],
                r["location"],
                upn2id.get((r["manager_upn"] or "").lower()),
                r["manager_upn"] or None,
                r["account_type"],
                b(r["privileged"]),
                b(r["vip"]),
                r["mfa_method"],
                r["status"],
                r["created"],
                host2id.get(r["workstation"]),
                r["workstation"] or None,
                r["notes"] or None,
                a_u,
                n,
            )
            for n, r in users
        ],
    )
    CRIT = {"Baja": 1, "Media": 2, "Alta": 3, "Crítica": 4}

    def tienda_of(r):
        m = re.match(r"Tienda (\d+)", r["location"] or "")
        if m:
            return f"T{int(m.group(1)):02d}"
        for t in tiendas:
            try:
                if ipaddress.ip_address(r["ip"]) in ipaddress.ip_network(t["red"]):
                    return t["tienda"]
            except Exception:
                pass
        return None

    con.executemany(
        f"INSERT INTO activo VALUES ({','.join('?'*19)})",
        [
            (
                r["asset_id"],
                r["hostname"],
                r["ip"] or None,
                idx.get("ip", r["ip"]) if is_ip(r["ip"]) else None,
                r["type"],
                r["os"],
                r["criticality"],
                CRIT.get(r["criticality"]),
                r["zone"],
                tienda_of(r),
                r["location"],
                r["business_service"],
                upn2id.get((r["owner_upn"] or "").lower()),
                r["owner_upn"] or None,
                b(r["internet_facing"]),
                b(r["edr_installed"]),
                r["description"] or None,
                a_a,
                n,
            )
            for n, r in assets
        ],
    )

    def expand(tok):
        m = re.match(r"^(.*?)(\d+)\.\.(\d+)$", tok.strip())
        return (
            [f"{m.group(1)}{i:0{len(m.group(2))}d}" for i in range(int(m.group(2)), int(m.group(3)) + 1)]
            if m
            else [tok.strip()]
        )

    links = {}
    for i, s in enumerate(svcs, 1):
        for _, r in assets:
            bs = r["business_service"] or ""
            if bs == s["servicio"] or bs.startswith(s["servicio"]):
                links.setdefault((r["asset_id"], i), set()).add("activos.business_service")
        for tok in re.split(r"[,;]", s["activos"] or ""):
            for h in expand(tok):
                if h in host2id:
                    links.setdefault((host2id[h], i), set()).add("servicios_negocio.activos")
    con.executemany(
        "INSERT INTO activo_servicio VALUES (?,?,?,?)",
        [
            (a, sv, "ambos" if len(m) == 2 else next(iter(m)), "confirmado" if len(m) == 2 else "una_fuente")
            for (a, sv), m in links.items()
        ],
    )
    con.executemany(
        "INSERT INTO vulnerabilidad(asset_id,hostname,cve,producto,severidad_cvss,cvss_valor,estado,detectada,notas,archivo_id,linea) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [
            (
                host2id.get(r["hostname"]),
                r["hostname"],
                r["id"],
                r["producto"],
                r["severidad_cvss"],
                (float(m.group()) if (m := re.search(r"\d+(\.\d+)?", r["severidad_cvss"] or "")) else None),
                r["estado"],
                r["detectada"],
                r["notas"] or None,
                aid["02_inventario/vulnerabilidades.csv"],
                n,
            )
            for n, r in rows_csv("02_inventario/vulnerabilidades.csv")
        ],
    )
    con.executemany(
        "INSERT INTO evento_rrhh(user_id,usuario,fecha,tipo,detalle,fecha_efectiva,archivo_id,linea) VALUES (?,?,?,?,?,?,?,?)",
        [
            (
                upn2id.get(r["usuario"].lower()),
                r["usuario"],
                r["fecha"],
                r["tipo"],
                r["detalle"],
                r["fecha_efectiva"],
                aid["02_inventario/eventos_rrhh.csv"],
                n,
            )
            for n, r in rows_csv("02_inventario/eventos_rrhh.csv")
        ],
    )
    con.executemany(
        "INSERT INTO cambio VALUES (?,?,?,?,?,?,?,?,?)",
        [
            (
                r["id"],
                r["titulo"],
                r["inicio"],
                r["fin"],
                r["solicitante"],
                r["detalle"],
                r["alcance"],
                aid["02_inventario/calendario_cambios.csv"],
                n,
            )
            for n, r in rows_csv("02_inventario/calendario_cambios.csv")
        ],
    )
    log("inventory loaded")

    # ---- intelligence
    def jl(rel):
        with open(D / rel, encoding="utf-8") as f:
            for n, l in enumerate(f, 1):
                if l.strip():
                    yield n, json.loads(l)

    for n, t in jl("05_inteligencia/ti_feed.jsonl"):
        iid = idx.get(t["indicator_type"], t["value"])
        con.execute(
            "INSERT OR REPLACE INTO inteligencia VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                iid,
                t.get("reputation"),
                t.get("confidence"),
                t.get("malware_family") or None,
                t.get("tags") or None,
                t.get("first_seen"),
                t.get("last_seen"),
                t.get("source"),
                t.get("note") or None,
                aid["05_inteligencia/ti_feed.jsonl"],
                n,
            ),
        )
    for n, r in rows_csv("05_inteligencia/geoip_asn.csv"):
        con.execute(
            "INSERT OR REPLACE INTO geoip VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                idx.get("ip", r["ip"]),
                r["country"],
                r["city"],
                r["asn"],
                r["as_org"],
                b(r["is_tor"]),
                b(r["is_vpn_provider"]),
                b(r["is_hosting"]),
                b(r["is_residential_proxy"]),
                aid["05_inteligencia/geoip_asn.csv"],
                n,
            ),
        )
    occ = []
    for n, s in jl("05_inteligencia/sandbox_informes.jsonl"):
        iid = idx.get("sha256", s["sha256"])
        con.execute(
            "INSERT INTO sandbox VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                iid,
                s.get("md5"),
                s.get("file_name"),
                s.get("verdict"),
                s.get("score"),
                s.get("malware_family"),
                s.get("analysis_env"),
                s.get("analyzed_at"),
                s.get("note") or None,
                aid["05_inteligencia/sandbox_informes.jsonl"],
                n,
                json.dumps(s, ensure_ascii=False),
            ),
        )
        if s.get("md5"):
            occ.append((idx.get("md5", s["md5"]), None, None, iid, "md5", "md5"))
        for k, t in (("domains", "domain"), ("ips", "ip"), ("urls", "url")):
            for j, v in enumerate(g(s, "network." + k) or []):
                occ.append((idx.get(t, v), None, None, iid, f"red_{t}", f"network.{k}[{j}]"))
    idx.flush()
    con.executemany(
        "INSERT INTO ocurrencia_indicador(indicador_id,alert_id,event_id,sandbox_id,rol,ruta) VALUES (?,?,?,?,?,?)", occ
    )
    log("intelligence loaded")
    # ---- rules
    con.executemany(
        "INSERT INTO regla VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [
            (
                r["rule_id"],
                r["nombre"],
                r["fuente"],
                r["severidad_base"],
                r["tactica"],
                r["tecnica_id"],
                r["tecnica"],
                r["runbook"],
                r["logica"],
                aid["01_contexto/catalogo_casos_de_uso.csv"],
                n,
            )
            for n, r in rows_csv("01_contexto/catalogo_casos_de_uso.csv")
        ],
    )
    # ---- alerts (+ alerta_evento, participacion, ocurrencias) - same entity extraction as the star schema (L2 compatible)
    user_key2id = {nuser(r["username"]): r["user_id"] for _, r in users}
    a_al = aid["03_alertas/alertas.jsonl"]
    al_rows, ae, part, occ = [], [], [], []
    for n, x in jl("03_alertas/alertas.jsonl"):
        m = x.get("mitre") or {}
        al_rows.append(
            (
                x["alert_id"],
                x["created_at"],
                x["rule_id"],
                x.get("status"),
                x.get("source_product"),
                x.get("rule_name"),
                x.get("severity"),
                x.get("description"),
                m.get("tactic"),
                m.get("technique_id"),
                m.get("technique"),
                x.get("runbook"),
                a_al,
                n,
                json.dumps(x, ensure_ascii=False),
            )
        )
        for pos, ev in enumerate(x.get("related_events") or []):
            ae.append((x["alert_id"], pos, ev))
        e = x.get("entities") or {}

        def P(tipo, v, ruta, rol=None):
            if not v:
                return
            uid = aid_ = None
            metodo, estado, ambito = None, "no_resuelto", "desconocido"
            if tipo == "user":
                k = nuser(v)
                uid = upn2id.get(str(v).lower()) or user_key2id.get(k)
                metodo = "upn" if "@" in str(v) else ("dominio\\usuario" if "\\" in str(v) else "username")
                if uid:
                    estado, ambito = "resuelto", "interno"
            elif tipo == "host":
                aid_ = host2id.get(v)
                metodo = "hostname"
                if aid_:
                    estado, ambito = "resuelto", "interno"
            elif tipo == "customer":
                ambito, estado, metodo = "cliente", "observado", "customer_id"
            elif tipo in ("cloud_identity", "bucket", "access_key"):
                ambito, estado, metodo = "cloud", "observado", tipo
                if tipo == "cloud_identity" and user_key2id.get(nuser(v)):
                    uid, estado = user_key2id[nuser(v)], "resuelto"
            elif tipo == "ai_session":
                ambito, estado, metodo = "cliente", "observado", "session_id"
            part.append((x["alert_id"], None, tipo, rol or tipo, ambito, str(v), uid, aid_, ruta, metodo, estado))

        def O(tipo, v, ruta, rol):
            if v:
                occ.append((idx.get(tipo, v), x["alert_id"], None, None, rol, ruta))

        for i, u in enumerate(e.get("users") or []):
            P("user", u.get("upn") if isinstance(u, dict) else u, f"entities.users[{i}].upn")
        for i, h in enumerate(e.get("hosts") or []):
            if isinstance(h, dict):
                P("host", h.get("hostname"), f"entities.hosts[{i}].hostname")
                if h.get("ip"):
                    O("ip", h["ip"], f"entities.hosts[{i}].ip", "ip_host")
            else:
                P("host", h, f"entities.hosts[{i}]")
        for k, t in (("ips", "ip"), ("domains", "domain"), ("urls", "url")):
            for i, v in enumerate(e.get(k) or []):
                O(t, v, f"entities.{k}[{i}]", t)
        for i, f in enumerate(e.get("files") or []):
            v = f.get("sha256") if isinstance(f, dict) else f
            if v and SHA.match(str(v)):
                O("sha256", v, f"entities.files[{i}].sha256", "file")
            else:
                P("file", (f.get("name") if isinstance(f, dict) else f), f"entities.files[{i}].name")
        for i, c in enumerate(e.get("customers") or []):
            P("customer", c.get("customer_id") if isinstance(c, dict) else c, f"entities.customers[{i}]")
        for i, p in enumerate(e.get("processes") or []):
            P("process", p.get("name"), f"entities.processes[{i}].name")
        cl = e.get("cloud")
        if isinstance(cl, dict):
            for k in ("identity", "new_user"):
                P("cloud_identity", cl.get(k), f"entities.cloud.{k}")
            P("bucket", cl.get("bucket"), "entities.cloud.bucket")
            P("access_key", cl.get("access_key"), "entities.cloud.access_key")
        if e.get("ai_session"):
            P("ai_session", e["ai_session"], "entities.ai_session")
    idx.flush()
    con.executemany(f"INSERT INTO alerta VALUES ({','.join('?'*15)})", al_rows)
    con.executemany("INSERT INTO alerta_evento VALUES (?,?,?)", ae)
    con.executemany(
        "INSERT INTO participacion(alert_id,event_id,tipo,rol,ambito,valor_observado,user_id,asset_id,ruta,metodo,estado) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        part,
    )
    con.executemany(
        "INSERT INTO ocurrencia_indicador(indicador_id,alert_id,event_id,sandbox_id,rol,ruta) VALUES (?,?,?,?,?,?)", occ
    )
    # ---- system results preserved from the previous fact_alert
    con.execute("""INSERT INTO resultado_alerta SELECT alert_id, user_key, hostname, context_key, event_id, dedup_hash, verdict,
                   final_severity, severity_rationale, confidence, action, triaged_at, authorised_by FROM fact_alert""")
    con.commit()
    log(
        f"alerta {len(al_rows)} | alerta_evento {len(ae)} | participacion(alert) {len(part)} | ocurrencias(alert) {len(occ)}"
    )


# ---------------------------------------------------------------- STAGE 2: events
FIELD = {  # source -> (action field, result field)
    "ad_events": ("event", "event_code"),
    "ai_gateway": ("guardrail.action", "guardrail.category"),
    "cicd_builds": ("step", "status"),
    "cloudtrail": ("eventName", "errorCode"),
    "dlp": ("action", "policy"),
    "ecom_account": ("event", None),
    "ecom_auth": (None, "result"),
    "edr_events": ("event_type", "details.action"),
    "email": ("action", "verdict"),
    "email_clicks": ("action", "verdict_at_click"),
    "idp_audit": ("operation", None),
    "idp_signins": (None, "result"),
    "sql_audit": ("statement_type", "rows_returned"),
    "vpn": ("action", "mfa_result"),
    "waf": ("action", "rule_id"),
    "dns": ("qtype", "rcode"),
    "firewall": ("action", "rule"),
    "proxy": ("action", "status"),
}


def event_entities(src, d):
    """-> participations [(tipo, valor, rol, ruta)], indicators [(tipo, valor, rol, ruta)], ip_dst"""
    P, O = [], []

    def p(t, path, rol):
        v = g(d, path)
        if v not in (None, ""):
            P.append((t, str(v), rol, path))

    def o(t, path, rol):
        v = g(d, path)
        if v in (None, ""):
            return
        tt = t or ind_type(v)
        if tt == "ip" and not is_ip(v):
            return
        if tt:
            O.append((tt, str(v), rol, path))

    ipd = None
    if src == "ad_events":
        p("user", "subject", "actor")
        p("user", "target", "objetivo")
        p("host", "src_host", "origen")
        p("host", "dc", "dc")
    elif src == "ai_gateway":
        p("customer", "customer_id", "actor")
        p("session", "session_id", "sesion")
        o("ip", "src_ip", "origen")
    elif src == "cicd_builds":
        p("host", "runner", "runner")
        p("user", "details.author", "autor")
    elif src == "cloudtrail":
        o("ip", "sourceIPAddress", "origen")
        p("cloud_identity", "userIdentity.userName", "actor")
        p("access_key", "userIdentity.accessKeyId", "credencial")
        p("bucket", "requestParameters.bucketName", "objetivo")
        p("cloud_identity", "requestParameters.userName", "objetivo")
    elif src == "dlp":
        p("user", "user", "actor")
        p("host", "hostname", "origen")
        o(None, "destination", "destino")
    elif src == "ecom_account":
        p("customer", "customer_id", "actor")
        o("ip", "src_ip", "origen")
    elif src == "ecom_auth":
        p("customer", "customer_id", "objetivo")
        o("ip", "src_ip", "origen")
        o("email", "email", "cuenta")
    elif src == "edr_events":
        p("user", "user", "actor")
        p("host", "hostname", "host")
        p("process", "process_name", "proceso")
        o("sha256", "sha256", "fichero")
    elif src == "email":
        o("email", "sender", "remitente")
        o("ip", "sender_ip", "origen")
        p("session", "message_id", "mensaje")
        for i, r in enumerate(d.get("recipients") or []):
            if str(r).lower().endswith("@tarvia.example"):
                P.append(("user", str(r), "destinatario", f"recipients[{i}]"))
            else:
                O.append(("email", str(r), "destinatario", f"recipients[{i}]"))
        for i, u in enumerate(d.get("urls") or []):
            O.append(("url", str(u), "url", f"urls[{i}]"))
        for i, a in enumerate(d.get("attachments") or []):
            if isinstance(a, dict) and a.get("sha256"):
                O.append(("sha256", a["sha256"], "adjunto", f"attachments[{i}].sha256"))
    elif src == "email_clicks":
        p("user", "user", "actor")
        o("url", "url", "url")
        p("session", "message_id", "mensaje")
        o("ip", "src_ip", "origen")
    elif src == "idp_audit":
        p("user", "actor_upn", "actor")
        o("ip", "src_ip", "origen")
    elif src == "idp_signins":
        p("user", "user_upn", "actor")
        o("ip", "src_ip", "origen")
        p("session", "session_id", "sesion")
        p("host", "device_id", "dispositivo")
    elif src == "sql_audit":
        p("user", "user", "actor")
        p("host", "client_host", "origen")
    elif src == "vpn":
        p("user", "user", "actor")
        o("ip", "src_ip", "origen")
        o("ip", "assigned_ip", "asignada")
        ipd = d.get("assigned_ip")
    elif src == "waf":
        o("ip", "src_ip", "origen")
        o("domain", "host", "destino")
    elif src == "dns":
        o("ip", "src_ip", "origen")
        p("host", "hostname", "host")
        o("domain", "query", "consulta")
        if is_ip(d.get("response")):
            o("ip", "response", "respuesta")
            ipd = d.get("response")
    elif src == "firewall":
        o("ip", "src_ip", "origen")
        o("ip", "dst_ip", "destino")
        ipd = d.get("dst_ip")
    elif src == "proxy":
        o("ip", "src_ip", "origen")
        p("host", "hostname", "host")
        p("user", "user", "actor")
        o("url", "url", "url")
        o("domain", "domain", "destino")
        o("ip", "dst_ip", "destino")
        ipd = d.get("dst_ip")
    return P, O, ipd


def stage_events(con, D):
    idx = Idx(con)
    aid = {r[0]: r[1] for r in con.execute("SELECT ruta, archivo_id FROM archivo_fuente")}
    upn2id = {r[0]: r[1] for r in con.execute("SELECT upn, user_id FROM usuario")}
    uk2id = {r[0]: r[1] for r in con.execute("SELECT user_key, user_id FROM usuario")}
    host2id = {r[0].lower(): r[1] for r in con.execute("SELECT hostname, asset_id FROM activo")}
    ip2asset = {r[0]: r[1] for r in con.execute("SELECT ip, asset_id FROM activo WHERE ip IS NOT NULL")}
    lines = {}
    for p in sorted((D / "04_logs").iterdir()):
        with open(p, encoding="utf-8") as f:
            for n, l in enumerate(f, 1):
                m = (
                    re.search(r'"?event_id"?\s*[:,]?\s*"?((?:[A-Z]+)-\d+)', l[:80])
                    if p.suffix == ".jsonl"
                    else re.match(r"([A-Z]+-\d+),", l)
                )
                if m:
                    lines[m.group(1)] = (aid["04_logs/" + p.name], n)
    log(f"line index {len(lines)}")
    ev, part, occ = [], [], []

    def flush():
        idx.flush()
        con.executemany(f"INSERT INTO evento VALUES ({','.join('?'*20)})", ev)
        con.executemany(
            "INSERT INTO participacion(alert_id,event_id,tipo,rol,ambito,valor_observado,user_id,asset_id,ruta,metodo,estado) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            part,
        )
        con.executemany(
            "INSERT INTO ocurrencia_indicador(indicador_id,alert_id,event_id,sandbox_id,rol,ruta) VALUES (?,?,?,?,?,?)",
            occ,
        )
        ev.clear()
        part.clear()
        occ.clear()

    for r in con.execute("SELECT * FROM dim_log"):
        d = json.loads(r["detail"])
        src = r["source"]
        P, O, ipd = event_entities(src, d)
        fa, fr = FIELD.get(src, (None, None))
        for t, v, rol, ruta in P:
            uid = aid_ = None
            metodo, estado, ambito = None, "no_resuelto", "desconocido"
            if t == "user":
                uid = upn2id.get(v.lower()) or uk2id.get(nuser(v))
                metodo = "upn" if "@" in v else ("dominio\\usuario" if "\\" in v else "username")
                if uid:
                    estado, ambito = "resuelto", "interno"
                elif "@" in v:
                    ambito = "externo"
            elif t == "host":
                aid_ = host2id.get(v.lower())
                metodo = "hostname"
                if aid_:
                    estado, ambito = "resuelto", "interno"
            elif t in ("customer", "session"):
                ambito, estado, metodo = ("cliente" if t == "customer" else "desconocido"), "observado", t
            elif t in ("cloud_identity", "access_key", "bucket"):
                ambito, estado, metodo = "cloud", "observado", t
                if t == "cloud_identity" and uk2id.get(nuser(v)):
                    uid, estado = uk2id[nuser(v)], "resuelto"
            elif t == "process":
                ambito, estado, metodo = "interno", "observado", "process_name"
            part.append((None, r["event_id"], t, rol, ambito, v, uid, aid_, ruta, metodo, estado))
        for t, v, rol, ruta in O:
            occ.append((idx.get(t, v), None, r["event_id"], None, rol, ruta))
            if (
                t == "ip"
                and PRIVATE.match(v)
                and v in ip2asset
                and src in ("firewall", "vpn")
                and rol in ("origen", "destino")
            ):
                part.append(
                    (None, r["event_id"], "host", rol, "interno", v, None, ip2asset[v], ruta, "ip_activo", "resuelto")
                )
        sip = r["src_ip"]
        arch, lin = lines.get(r["event_id"], (aid.get(f"04_logs/{src}.jsonl") or aid.get(f"04_logs/{src}.csv"), None))
        ev.append(
            (
                r["event_id"],
                src,
                r["timestamp"],
                r["action"],
                fa,
                r["result"],
                fr,
                sip,
                idx.get("ip", sip) if sip and is_ip(sip) else None,
                ipd,
                idx.get("ip", ipd) if ipd and is_ip(ipd) else None,
                r["dst"],
                r["user_key"],
                r["customer_id"],
                r["hostname"],
                r["sha256"],
                r["ref_id"],
                arch,
                lin,
                r["detail"],
            )
        )
        if len(ev) >= 50000:
            flush()
    flush()
    con.commit()
    log(
        f'evento {con.execute("SELECT COUNT(*) FROM evento").fetchone()[0]} | participacion {con.execute("SELECT COUNT(*) FROM participacion").fetchone()[0]} '
        f'| ocurrencias {con.execute("SELECT COUNT(*) FROM ocurrencia_indicador").fetchone()[0]} | indicador {con.execute("SELECT COUNT(*) FROM indicador").fetchone()[0]}'
    )


# ---------------------------------------------------------------- STAGE 3: switch (rebuild system tables, drop old, views)
COMPAT_VIEWS = r"""
CREATE VIEW dim_log AS
  SELECT event_id, fuente AS source, timestamp, user_key, customer_id, hostname, ip_origen AS src_ip, destino AS dst,
         accion AS action, resultado AS result, sha256, ref_id, datos_json AS detail FROM evento;
CREATE VIEW dim_user AS
  SELECT u.user_key, u.user_id, u.username, u.upn, u.display_name, u.department, u.title, u.location, u.manager_upn,
         u.account_type, u.privileged, u.vip, u.mfa_method, u.status, u.workstation, u.notes,
         h.tipo AS hr_event, h.fecha AS hr_event_date, h.fecha_efectiva AS hr_fecha_efectiva, h.detalle AS hr_detalle
  FROM usuario u LEFT JOIN evento_rrhh h ON h.rrhh_id = (SELECT rrhh_id FROM evento_rrhh x WHERE x.user_id = u.user_id ORDER BY fecha DESC LIMIT 1);
CREATE VIEW dim_vulnerability AS
  SELECT a.hostname, a.asset_id, a.ip, a.type, a.os, a.criticality, a.criticality_level, a.zona AS zone, a.location,
         a.business_service,
         (SELECT s.criticidad FROM activo_servicio x JOIN servicio_negocio s USING(servicio_id) WHERE x.asset_id=a.asset_id
          ORDER BY CASE s.criticidad WHEN 'Crítica' THEN 0 WHEN 'Alta' THEN 1 WHEN 'Media' THEN 2 ELSE 3 END LIMIT 1) AS service_criticidad,
         (SELECT s.responsable FROM activo_servicio x JOIN servicio_negocio s USING(servicio_id) WHERE x.asset_id=a.asset_id
          ORDER BY CASE s.criticidad WHEN 'Crítica' THEN 0 WHEN 'Alta' THEN 1 WHEN 'Media' THEN 2 ELSE 3 END LIMIT 1) AS service_responsable,
         a.owner_upn, a.internet_facing, a.edr_installed, a.description,
         (SELECT COUNT(*) FROM vulnerabilidad v WHERE v.asset_id=a.asset_id AND v.estado='abierta') AS open_vuln_count,
         (SELECT MAX(cvss_valor) FROM vulnerabilidad v WHERE v.asset_id=a.asset_id AND v.estado='abierta') AS max_cvss_open,
         (SELECT GROUP_CONCAT(v.cve||':'||v.producto||':'||v.severidad_cvss||':'||v.estado, ' ; ') FROM vulnerabilidad v WHERE v.asset_id=a.asset_id) AS cve_ids,
         (SELECT GROUP_CONCAT(v.notas, ' ; ') FROM vulnerabilidad v WHERE v.asset_id=a.asset_id) AS vuln_notes
  FROM activo a;
CREATE VIEW dim_context AS
  SELECT i.valor AS context_key, i.tipo AS context_type, t.reputacion AS reputation, t.confianza AS confidence,
         t.malware_family, t.tags, t.first_seen, t.last_seen, t.fuente AS ti_source, t.nota AS ti_note,
         g.pais AS country, g.ciudad AS city, g.asn, g.as_org, g.is_tor, g.is_vpn_provider, g.is_hosting, g.is_residential_proxy,
         s.file_name AS sandbox_file_name, s.veredicto AS sandbox_verdict, s.score AS sandbox_score, s.malware_family AS sandbox_family,
         (SELECT GROUP_CONCAT(value, ',') FROM json_each(s.datos_json, '$.mitre')) AS sandbox_mitre,
         json_extract(s.datos_json, '$.behaviors') AS sandbox_behaviors, json_extract(s.datos_json, '$.network') AS sandbox_network,
         NULL AS change_title, NULL AS change_start, NULL AS change_end, NULL AS change_requester, NULL AS change_detail, NULL AS change_scope
  FROM indicador i LEFT JOIN inteligencia t USING(indicador_id) LEFT JOIN geoip g USING(indicador_id) LEFT JOIN sandbox s USING(indicador_id)
  WHERE t.indicador_id IS NOT NULL OR g.indicador_id IS NOT NULL OR s.indicador_id IS NOT NULL
  UNION ALL
  SELECT cambio_id, 'change', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         NULL, NULL, NULL, NULL, NULL, NULL, NULL, titulo, inicio, fin, solicitante, condiciones, alcance FROM cambio;
CREATE VIEW dim_rule AS
  SELECT r.rule_id, r.nombre, r.fuente, r.severidad_base, r.tactica, r.tecnica_id, r.tecnica, r.runbook, r.logica,
         trim(substr(d.texto, instr(d.texto, '## Comprobaciones') + 18,
                     CASE WHEN instr(d.texto, '## Decisi') > 0 THEN instr(d.texto, '## Decisi') - instr(d.texto, '## Comprobaciones') - 18 ELSE 100000 END)) AS runbook_checks,
         CASE WHEN instr(d.texto, '## Decisi') > 0 THEN trim(substr(d.texto, instr(d.texto, '## Decisi') + 12)) END AS runbook_decision
  FROM regla r LEFT JOIN documento d ON d.codigo = r.runbook;
CREATE VIEW fact_alert AS
  SELECT a.alert_id, a.fecha AS created_at, a.rule_id, a.tecnica_id AS technique_id, r.user_key, r.hostname, r.context_key, r.event_id,
         a.source_product, a.rule_name, a.severidad AS rule_severity, a.estado AS status, a.tactica AS mitre_tactic, a.descripcion AS description,
         a.runbook, json_extract(a.datos_json, '$.entities') AS entities, json_extract(a.datos_json, '$.evidence') AS evidence,
         r.dedup_hash, r.verdict, r.final_severity, r.severity_rationale, r.confidence, r.action, r.triaged_at, r.authorised_by
  FROM alerta a LEFT JOIN resultado_alerta r USING(alert_id);
CREATE TRIGGER fact_alert_update INSTEAD OF UPDATE ON fact_alert BEGIN
  INSERT INTO resultado_alerta(alert_id) SELECT NEW.alert_id WHERE NOT EXISTS (SELECT 1 FROM resultado_alerta WHERE alert_id = NEW.alert_id);
  UPDATE resultado_alerta SET verdict=NEW.verdict, final_severity=NEW.final_severity, severity_rationale=NEW.severity_rationale,
         confidence=NEW.confidence, action=NEW.action, triaged_at=NEW.triaged_at, authorised_by=NEW.authorised_by,
         dedup_hash=NEW.dedup_hash, user_key=NEW.user_key, hostname=NEW.hostname, context_key=NEW.context_key, event_id=NEW.event_id
  WHERE alert_id = NEW.alert_id;
END;
CREATE VIEW bridge_alert_entity AS
  SELECT alert_id, entity_type, entity_value, user_key, hostname, context_key, orden FROM (
  SELECT p.alert_id, p.tipo AS entity_type, p.valor_observado AS entity_value, u.user_key, a.hostname, NULL AS context_key,
         (CASE WHEN p.ruta LIKE 'entities.users%' THEN 1 WHEN p.ruta LIKE 'entities.hosts%' THEN 2 WHEN p.ruta LIKE 'entities.ips%' THEN 3
            WHEN p.ruta LIKE 'entities.domains%' THEN 4 WHEN p.ruta LIKE 'entities.urls%' THEN 5 WHEN p.ruta LIKE 'entities.files%' THEN 6
            WHEN p.ruta LIKE 'entities.customers%' THEN 7 WHEN p.ruta LIKE 'entities.processes%' THEN 8
            WHEN p.ruta = 'entities.cloud.identity' THEN 9 WHEN p.ruta = 'entities.cloud.new_user' THEN 10 WHEN p.ruta = 'entities.cloud.bucket' THEN 11
            WHEN p.ruta = 'entities.cloud.access_key' THEN 12 ELSE 13 END) * 100000
         + COALESCE(CAST(substr(p.ruta, instr(p.ruta, '[') + 1, instr(p.ruta, ']') - instr(p.ruta, '[') - 1) AS INTEGER), 0) * 10
         + (CASE WHEN p.ruta LIKE '%.ip' THEN 1 ELSE 0 END) AS orden
  FROM participacion p LEFT JOIN usuario u ON u.user_id = p.user_id AND p.tipo = 'user' LEFT JOIN activo a ON a.asset_id = p.asset_id
  WHERE p.alert_id IS NOT NULL
  UNION ALL
  SELECT o.alert_id, CASE i.tipo WHEN 'sha256' THEN 'file' ELSE i.tipo END, i.valor, NULL, NULL,
         CASE WHEN EXISTS (SELECT 1 FROM inteligencia t WHERE t.indicador_id = i.indicador_id)
                OR EXISTS (SELECT 1 FROM geoip g WHERE g.indicador_id = i.indicador_id)
                OR EXISTS (SELECT 1 FROM sandbox s WHERE s.indicador_id = i.indicador_id) THEN i.valor END,
         (CASE WHEN o.ruta LIKE 'entities.users%' THEN 1 WHEN o.ruta LIKE 'entities.hosts%' THEN 2 WHEN o.ruta LIKE 'entities.ips%' THEN 3
            WHEN o.ruta LIKE 'entities.domains%' THEN 4 WHEN o.ruta LIKE 'entities.urls%' THEN 5 WHEN o.ruta LIKE 'entities.files%' THEN 6
            WHEN o.ruta LIKE 'entities.customers%' THEN 7 WHEN o.ruta LIKE 'entities.processes%' THEN 8
            WHEN o.ruta = 'entities.cloud.identity' THEN 9 WHEN o.ruta = 'entities.cloud.new_user' THEN 10 WHEN o.ruta = 'entities.cloud.bucket' THEN 11
            WHEN o.ruta = 'entities.cloud.access_key' THEN 12 ELSE 13 END) * 100000
         + COALESCE(CAST(substr(o.ruta, instr(o.ruta, '[') + 1, instr(o.ruta, ']') - instr(o.ruta, '[') - 1) AS INTEGER), 0) * 10
         + (CASE WHEN o.ruta LIKE '%.ip' THEN 1 ELSE 0 END)
  FROM ocurrencia_indicador o JOIN indicador i USING(indicador_id) WHERE o.alert_id IS NOT NULL)
  ORDER BY alert_id, orden;   -- original order of the entities inside the alert JSON (deterministic re-runs)
CREATE VIEW bridge_alert_event AS
  SELECT ae.alert_id, ae.event_id, 1 AS in_dim_log FROM alerta_evento ae;
CREATE VIEW v_common_log_matches AS
  SELECT e.event_id, e.fuente AS source_product, e.timestamp, e.accion AS action, e.resultado AS result,
         p.pattern_id, p.pattern_name, p.classification, p.filtering_action,
         m.matched_by, m.match_confidence
  FROM evento e
  JOIN log_pattern_match m ON m.event_id = e.event_id
  JOIN common_log_pattern p ON p.pattern_id = m.pattern_id;
CREATE VIEW v_useful_logs AS
  SELECT e.*
  FROM evento e
  WHERE NOT EXISTS (
    SELECT 1
    FROM log_pattern_match m
    JOIN common_log_pattern p ON p.pattern_id = m.pattern_id
    WHERE m.event_id = e.event_id AND p.enabled = 1 AND p.filtering_action = 'hide_from_triage'
  );
CREATE VIEW v_common_log_candidates AS
  SELECT accion AS action, resultado AS result, COUNT(*) AS event_count,
         COUNT(DISTINCT fuente) AS product_count, COUNT(DISTINCT event_id) AS distinct_event_count
  FROM evento
  GROUP BY accion, resultado
  HAVING COUNT(DISTINCT fuente) > 1;
"""

INDEXES = r"""
CREATE INDEX ix_evento_user_ts   ON evento(user_key, timestamp);
CREATE INDEX ix_evento_host_ts   ON evento(hostname, timestamp);
CREATE INDEX ix_evento_src_ts    ON evento(ip_origen, timestamp);
CREATE INDEX ix_evento_dst       ON evento(destino);
CREATE INDEX ix_evento_sha       ON evento(sha256);
CREATE INDEX ix_evento_ref       ON evento(ref_id);
CREATE INDEX ix_evento_cust_ts   ON evento(customer_id, timestamp);
CREATE INDEX ix_evento_fuente_ts ON evento(fuente, timestamp);
CREATE INDEX ix_common_pattern_fingerprint ON common_log_pattern(normalized_fingerprint);
CREATE INDEX ix_common_pattern_source_action ON common_log_pattern(source_product, action, result);
CREATE INDEX ix_log_pattern_match_pattern ON log_pattern_match(pattern_id);
CREATE INDEX ix_log_pattern_match_event ON log_pattern_match(event_id);
CREATE INDEX ix_alerta_fecha     ON alerta(fecha);
CREATE INDEX ix_alerta_rule      ON alerta(rule_id);
CREATE INDEX ix_ae_event         ON alerta_evento(event_id);
CREATE INDEX ix_part_alert       ON participacion(alert_id);
CREATE INDEX ix_part_event       ON participacion(event_id);
CREATE INDEX ix_part_user        ON participacion(user_id);
CREATE INDEX ix_part_asset       ON participacion(asset_id);
CREATE INDEX ix_part_valor       ON participacion(tipo, valor_observado);
CREATE INDEX ix_occ_ind          ON ocurrencia_indicador(indicador_id);
CREATE INDEX ix_occ_alert        ON ocurrencia_indicador(alert_id);
CREATE INDEX ix_occ_event        ON ocurrencia_indicador(event_id);
CREATE INDEX ix_ind_norm         ON indicador(normalizado);
CREATE INDEX ix_vuln_asset       ON vulnerabilidad(asset_id);
CREATE INDEX ix_rrhh_user        ON evento_rrhh(user_id);
CREATE INDEX ix_res_dedup        ON resultado_alerta(dedup_hash);
CREATE INDEX ix_res_user         ON resultado_alerta(user_key);
CREATE INDEX ix_res_host         ON resultado_alerta(hostname);
"""


def rebuild(con, name, new_ddl):
    cols = [r[1] for r in con.execute(f"PRAGMA table_info({name})")]
    con.execute(f"ALTER TABLE {name} RENAME TO _old_{name}")
    con.execute(new_ddl)
    newcols = [r[1] for r in con.execute(f"PRAGMA table_info({name})")]
    common = [c for c in cols if c in newcols]
    con.execute(f"INSERT INTO {name}({','.join(common)}) SELECT {','.join(common)} FROM _old_{name}")
    con.execute(f"DROP TABLE _old_{name}")


def stage_switch(con, D):
    con.execute("PRAGMA foreign_keys=OFF")
    old_views = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='view'")]
    view_sql = {r[0]: r[1] for r in con.execute("SELECT name, sql FROM sqlite_master WHERE type='view'")}
    for v in old_views:
        con.execute(f"DROP VIEW {v}")
    for t in (
        "bridge_alert_entity",
        "bridge_alert_event",
        "fact_alert",
        "dim_log",
        "dim_user",
        "dim_vulnerability",
        "dim_context",
        "dim_rule",
    ):
        con.execute(f"DROP TABLE IF EXISTS {t}")
    rebuild(
        con,
        "fact_incident",
        """CREATE TABLE fact_incident (
      incident_id TEXT PRIMARY KEY, title TEXT, first_seen TEXT, last_seen TEXT, alert_count INTEGER,
      primary_user_key TEXT REFERENCES usuario(user_key), primary_hostname TEXT REFERENCES activo(hostname),
      tactics_covered INTEGER, max_kill_chain_stage INTEGER, verdict TEXT, final_severity TEXT, severity_rationale TEXT,
      confidence REAL, escalate_n2 INTEGER, status TEXT, related_incident_id TEXT REFERENCES fact_incident(incident_id),
      patient_zero TEXT, initial_access TEXT REFERENCES dim_mitre(technique_id), scope TEXT, root_cause TEXT, containment_plan TEXT,
      open_questions TEXT, created_at TEXT, updated_at TEXT, escalation_reasons TEXT, authorised_by TEXT, triage_stage TEXT,
      eradication_and_recovery TEXT, notifications TEXT, detection_gaps TEXT, related_incidents TEXT)""",
    )
    rebuild(
        con,
        "bridge_alert_incident",
        """CREATE TABLE bridge_alert_incident (
      alert_id TEXT NOT NULL REFERENCES alerta(alert_id), incident_id TEXT NOT NULL REFERENCES fact_incident(incident_id),
      link_reason TEXT, link_window TEXT, link_score REAL, is_duplicate INTEGER DEFAULT 0, is_authorised INTEGER DEFAULT 0,
      PRIMARY KEY (alert_id, incident_id))""",
    )
    rebuild(
        con,
        "fact_attack_step",
        """CREATE TABLE fact_attack_step (
      step_id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL REFERENCES fact_incident(incident_id),
      step_order INTEGER NOT NULL, timestamp TEXT NOT NULL, event_id TEXT REFERENCES evento(event_id),
      alert_id TEXT REFERENCES alerta(alert_id), technique_id TEXT REFERENCES dim_mitre(technique_id),
      user_key TEXT, hostname TEXT, context_key TEXT,
      evidence_origin TEXT CHECK (evidence_origin IN ('alert','hidden_log','context')), description TEXT, confidence REAL)""",
    )
    con.executescript(COMPAT_VIEWS)
    con.executescript(INDEXES)
    con.execute("CREATE INDEX IF NOT EXISTS ix_bai_incident ON bridge_alert_incident(incident_id)")
    con.execute("CREATE INDEX IF NOT EXISTS ix_step_incident ON fact_attack_step(incident_id, step_order)")
    for v in old_views:  # analytical views (v_*) recreated on top of the compatibility names
        if v.startswith("v_"):
            con.execute(view_sql[v])
    con.execute("PRAGMA foreign_keys=ON")
    con.commit()
    bad = con.execute("PRAGMA foreign_key_check").fetchall()
    log(f"switch done | foreign_key_check violations: {len(bad)} {bad[:5]}")


def stage_docs(con, D):
    """(re)load project documentation into archivo_fuente / documento (idempotent, by path)."""
    paths = [ROOT / x for x in PROJECT_DOCS if (ROOT / x).exists()]
    for gl in PROJECT_GLOBS:
        paths += sorted(ROOT.glob(gl))
    n = 0
    for p in paths:
        raw = p.read_bytes()
        rel = "proyecto/" + str(p.relative_to(ROOT)).replace("\\", "/")
        fmt = p.suffix.lower().lstrip(".")
        row = con.execute("SELECT archivo_id FROM archivo_fuente WHERE ruta=?", (rel,)).fetchone()
        if row:
            aid = row[0]
            con.execute(
                "UPDATE archivo_fuente SET bytes=?, sha256=?, original=? WHERE archivo_id=?",
                (len(raw), hashlib.sha256(raw).hexdigest(), zlib.compress(raw, 6), aid),
            )
        else:
            aid = con.execute(
                "INSERT INTO archivo_fuente(ruta,rol,formato,bytes,sha256,filas,compresion,original) VALUES (?,?,?,?,?,?,?,?)",
                (rel, "proyecto", fmt, len(raw), hashlib.sha256(raw).hexdigest(), None, "zlib", zlib.compress(raw, 6)),
            ).lastrowid
        if fmt == "png":
            tipo, text = "diagrama", f"Diagrama ({p.name}); imagen íntegra en archivo_fuente.original"
        elif "reports" in rel:
            tipo, text = "informe_incidente", raw.decode("utf-8", "replace")
        else:
            tipo, text = "proyecto", raw.decode("utf-8", "replace")
        code = ("INF_" if tipo == "informe_incidente" else "PRJ_") + re.sub(r"\W+", "_", p.stem).upper()
        title = next((l.lstrip("# ").strip() for l in text.splitlines() if l.strip()), p.name)[:200]
        con.execute("INSERT OR REPLACE INTO documento VALUES (?,?,?,?,?)", (aid, code, tipo, title, text))
        n += 1
    con.commit()
    log(f"project documents loaded: {n}")


def stage_finish(con, D):
    con.execute("ANALYZE")
    con.commit()
    con.execute("VACUUM")
    log("vacuum done")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(ROOT / "db" / "tarvia_soc.sqlite"))
    ap.add_argument("--data", default=str(ROOT / "docs"))
    ap.add_argument("--stage", default="all", choices=["all", "base", "events", "switch", "docs", "finish"])
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")
    D = pathlib.Path(a.data).resolve()
    for st, fn in (
        ("base", stage_base),
        ("events", stage_events),
        ("switch", stage_switch),
        ("docs", stage_docs),
        ("finish", stage_finish),
    ):
        if a.stage in ("all", st):
            log("stage", st)
            fn(con, D)
    con.close()


if __name__ == "__main__":
    main()
