"""Reduced star-join schema: fact_alert + 5 dimensions (relevant fields only)."""

import html
import pathlib
import subprocess

OUT = pathlib.Path(__file__).parent

# (column, tag, source/comment)   tag: PK, FK, M (measure / triage output), A (attribute), J (json)
T = {
    "fact_alert": (
        "FACT · alertas.jsonl (11,061)",
        "#c0392b",
        [
            ("alert_id", "PK", ""),
            ("created_at", "A", "UTC"),
            ("rule_id", "FK", "→ dim_rule"),
            ("user_key", "FK", "→ dim_user"),
            ("hostname", "FK", "→ dim_vulnerability"),
            ("context_key", "FK", "→ dim_context (IOC / change)"),
            ("event_id", "FK", "→ dim_log (related_events)"),
            ("source_product", "A", ""),
            ("rule_severity", "A", "severity of the rule"),
            ("evidence", "J", "attacker-controllable"),
            ("verdict", "M", "TP / BTP / FP / needs_more_info"),
            ("final_severity", "M", "policy matrix ±1"),
            ("confidence", "M", "0–1"),
            ("ticket_id", "M", "alert grouping (N:1)"),
            ("action", "M", "close / escalate / contain"),
        ],
    ),
    "dim_rule": (
        "RULES · catalogo_casos_de_uso.csv + runbooks",
        "#7d8b12",
        [
            ("rule_id", "PK", ""),
            ("nombre", "A", ""),
            ("fuente", "A", ""),
            ("severidad_base", "A", "matrix input (row)"),
            ("tactica / tecnica_id", "A", "MITRE"),
            ("runbook", "A", "RB-01..10"),
            ("runbook_checks", "A", "investigation plan"),
        ],
    ),
    "dim_user": (
        "USERS · usuarios.csv + eventos_rrhh.csv",
        "#1f5f9e",
        [
            ("user_key", "PK", "lower(username)"),
            ("upn / username", "A", "join normalisation"),
            ("department / title", "A", ""),
            ("account_type", "A", "user / service / admin"),
            ("privileged", "A", "+1 severity"),
            ("vip", "A", "+1 severity"),
            ("mfa_method", "A", ""),
            ("status", "A", ""),
            ("hr_event / fecha_efectiva", "A", "leaver, role change"),
        ],
    ),
    "dim_vulnerability": (
        "VULNERABILITIES · vulnerabilidades.csv + activos.csv + servicios_negocio.csv",
        "#2e7d32",
        [
            ("hostname", "PK", ""),
            ("criticality", "A", "matrix input (column)"),
            ("business_service / criticidad", "A", "approver for isolation"),
            ("zone", "A", "incl. OT"),
            ("internet_facing", "A", ""),
            ("edr_installed", "A", ""),
            ("cve_id / producto", "A", ""),
            ("severidad_cvss / estado", "A", "open vs patched"),
        ],
    ),
    "dim_context": (
        "CONTEXT + INTELLIGENCE · ti_feed, geoip_asn, sandbox, calendario_cambios",
        "#b8860b",
        [
            ("context_key", "PK", "indicator value or change id"),
            ("context_type", "A", "ioc / ip / file / change"),
            ("reputation / confidence", "A", "TIP (unknown ≠ clean)"),
            ("malware_family / tags", "A", "TIP / sandbox"),
            ("country / asn / as_org", "A", "GeoIP"),
            ("is_tor / is_hosting / is_vpn", "A", "GeoIP"),
            ("sandbox_verdict / score", "A", "sandbox"),
            ("change_window / scope", "A", "→ benign_true_positive"),
        ],
    ),
    "dim_log": (
        "LOGS · unified view over 18 sources (814k events)",
        "#3b6fb6",
        [
            ("event_id", "PK", "prefix = source"),
            ("source", "A", "proxy, edr, idp_signins, ..."),
            ("timestamp", "A", "UTC"),
            ("user_key", "A", "normalised"),
            ("hostname", "A", ""),
            ("src_ip / dst", "A", "IP, domain or URL"),
            ("action / result", "A", "allowed, blocked, success"),
            ("sha256", "A", "EDR / email"),
            ("detail", "J", "raw record (untrusted)"),
        ],
    ),
}
TAG = {
    "PK": ("#fff2cc", "PK"),
    "FK": ("#e8f0fe", "FK"),
    "M": ("#efe3f7", "M"),
    "A": ("#ffffff", "&#160;"),
    "J": ("#fde2e2", "{ }"),
}


def port(c):
    return "p" + "".join(ch if ch.isalnum() else "_" for ch in c)


def node(name, sub, head, cols, big=False):
    w = "190" if big else "170"
    r = [
        f'<TR><TD COLSPAN="3" BGCOLOR="{head}"><FONT COLOR="white" POINT-SIZE="{20 if big else 17}"><B>{name}</B></FONT></TD></TR>',
        f'<TR><TD COLSPAN="3" BGCOLOR="{head}"><FONT COLOR="white" POINT-SIZE="10">{html.escape(sub)}</FONT></TD></TR>',
    ]
    for c, t, note in cols:
        bg, lab = TAG[t]
        b = ("<B>", "</B>") if t in ("PK", "FK") else ("", "")
        r.append(
            f'<TR><TD BGCOLOR="{bg}" WIDTH="26" PORT="{port(c)}_l"><FONT POINT-SIZE="10">{lab}</FONT></TD>'
            f'<TD ALIGN="LEFT" BGCOLOR="{bg}" PORT="{port(c)}" WIDTH="{w}"><FONT POINT-SIZE="12">{b[0]}{html.escape(c)}{b[1]}</FONT></TD>'
            f'<TD ALIGN="LEFT" BGCOLOR="{bg}" PORT="{port(c)}_r"><FONT POINT-SIZE="10" COLOR="#666666">{html.escape(note) or "&#160;"}</FONT></TD></TR>'
        )
    return f'"{name}" [label=<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">{"".join(r)}</TABLE>>];'


POS = {
    "fact_alert": (0, 0),
    "dim_rule": (-7.2, 4.3),
    "dim_user": (-7.2, -4.3),
    "dim_context": (7.4, 4.3),
    "dim_vulnerability": (7.4, -4.3),
    "dim_log": (0, -8.4),
}
g = [
    "graph G {",
    'graph [layout=neato, splines=curved, forcelabels=true, overlap=false, pad=0.5, fontname="Helvetica",',
    ' label=<<FONT POINT-SIZE="28"><B>Tarvia SOC — Star-join schema for L1 triage</B></FONT><BR/>'
    '<FONT POINT-SIZE="14">Fact table: alerts · Dimensions: rules, users, vulnerabilities (asset exposure), context + intelligence, logs</FONT>>, labelloc=t];',
    'node [shape=plaintext, fontname="Helvetica"]; edge [penwidth=2.2, fontname="Helvetica", fontsize=12];',
]
for n, (sub, head, cols) in T.items():
    x, y = POS[n]
    g.append(node(n, sub, head, cols, big=(n == "fact_alert")).replace("];", f', pos="{x},{y}!"];'))
E = [
    ("rule_id", "dim_rule", "rule_id", "N:1"),
    ("user_key", "dim_user", "user_key", "N:1"),
    ("hostname", "dim_vulnerability", "hostname", "N:1"),
    ("context_key", "dim_context", "context_key", "N:M*"),
    ("event_id", "dim_log", "event_id", "N:M*"),
]
SIDE = {
    "dim_rule": ("w", "e"),
    "dim_user": ("w", "e"),
    "dim_context": ("e", "w"),
    "dim_vulnerability": ("e", "w"),
    "dim_log": (None, None),
}
for fc, d, pk, card in E:
    col = T[d][1]
    a, b = SIDE[d]
    if a:
        fs = "_l" if a == "w" else "_r"
        ds = "_r" if b == "e" else "_l"
        src = f'"fact_alert":{port(fc)}{fs}:{a}'
        dst = f'"{d}":{port(pk)}{ds}:{b}'
    else:
        src = '"fact_alert":s'
        dst = f'"{d}":n'
    g.append(f'{src} -- {dst} [color="{col}", xlabel="{fc} ({card})", fontcolor="{col}"];')
g.append(
    'legend [pos="-7.2,-9.6!", label=<<TABLE BORDER="1" CELLBORDER="0" CELLSPACING="2" CELLPADDING="3" BGCOLOR="#fafafa">'
    '<TR><TD COLSPAN="2"><B>Legend</B></TD></TR>'
    '<TR><TD BGCOLOR="#fff2cc">PK</TD><TD ALIGN="LEFT">Primary key</TD></TR>'
    '<TR><TD BGCOLOR="#e8f0fe">FK</TD><TD ALIGN="LEFT">Foreign key to a dimension</TD></TR>'
    '<TR><TD BGCOLOR="#efe3f7">M</TD><TD ALIGN="LEFT">Triage output computed by the system</TD></TR>'
    '<TR><TD BGCOLOR="#fde2e2">{ }</TD><TD ALIGN="LEFT">JSON, attacker-controllable: data, never instructions</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT">* N:M resolved with a bridge (alert_id, key);</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT">  the FK shown is the primary entity of the alert</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT">final_severity = matrix(dim_rule.severidad_base,</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT">  max criticality of dim_vulnerability / dim_user) ± 1</TD></TR>'
    "</TABLE>>];"
)
g.append("}")
dot = OUT / "star_schema_alerts.dot"
dot.write_text("\n".join(g), encoding="utf-8")
for fmt in ("png", "svg"):
    subprocess.run(
        [
            "neato",
            "-n2" if False else "-Tpng" if fmt == "png" else "-Tsvg",
            "-Gdpi=130" if fmt == "png" else "-Gdpi=72",
            str(dot),
            "-o",
            str(OUT / f"star_schema_alerts.{fmt}"),
        ],
        check=True,
    )
print("ok")
