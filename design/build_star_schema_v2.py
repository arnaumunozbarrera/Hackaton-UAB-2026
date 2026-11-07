"""v2: star-join schema extended with L2 correlation, L3 attack-chain reconstruction and MITRE ATT&CK."""

import html
import pathlib
import subprocess

OUT = pathlib.Path(__file__).parent
L1, L2, L3, DIM, MIT = "#c0392b", "#6c3483", "#0e6655", None, "#34495e"

T = {
    "fact_alert": (
        "L1 · FACT · alertas.jsonl (11,061)",
        L1,
        [
            ("alert_id", "PK", ""),
            ("created_at", "A", "UTC"),
            ("rule_id", "FK", "→ dim_rule"),
            ("technique_id", "N", "→ dim_mitre"),
            ("user_key", "FK", "→ dim_user"),
            ("hostname", "FK", "→ dim_vulnerability"),
            ("context_key", "FK", "→ dim_context (N:M)"),
            ("event_id", "FK", "→ dim_log (N:M)"),
            ("source_product", "A", ""),
            ("rule_severity", "A", "matrix row"),
            ("evidence", "J", "attacker-controllable"),
            ("dedup_hash", "N", "rule + entities + window"),
            ("verdict", "M", "TP / BTP / FP / needs_more_info"),
            ("final_severity", "M", "matrix ±1"),
            ("confidence", "M", "0–1"),
            ("action", "M", "close / escalate / contain"),
        ],
    ),
    "bridge_alert_incident": (
        "L2 · CORRELATION · alert ↔ incident",
        L2,
        [
            ("alert_id", "PK", "→ fact_alert"),
            ("incident_id", "PK", "→ fact_incident"),
            ("link_reason", "N", "shared user / host / IOC / message_id / session"),
            ("link_window", "N", "±24 h or entity-persistent"),
            ("link_score", "N", "0–1"),
            ("is_duplicate", "N", "same dedup_hash"),
            ("is_authorised", "N", "matched change → BTP"),
        ],
    ),
    "fact_incident": (
        "L2 + L3 · FACT · one ticket per intrusion",
        L2,
        [
            ("incident_id", "PK", "= ticket_id"),
            ("first_seen / last_seen", "N", "may span days"),
            ("alert_count", "N", ""),
            ("primary_user_key", "N", "→ dim_user"),
            ("primary_hostname", "N", "→ dim_vulnerability"),
            ("tactics_covered", "N", "distinct ATT&CK tactics"),
            ("max_kill_chain_stage", "N", "from dim_mitre"),
            ("verdict / final_severity", "M", "chain rule (policy §5)"),
            ("escalate_n2", "M", "mandatory criteria"),
            ("related_incident_id", "N", "self-FK"),
            ("patient_zero", "N", "L3"),
            ("initial_access", "N", "L3 · technique"),
            ("scope", "J", "users, hosts, services, customers"),
            ("root_cause / confidence", "M", "L3"),
        ],
    ),
    "fact_attack_step": (
        "L3 · FACT · reconstructed timeline",
        L3,
        [
            ("step_id", "PK", ""),
            ("incident_id", "N", "→ fact_incident"),
            ("step_order", "N", "chronological"),
            ("timestamp", "N", "UTC"),
            ("event_id", "N", "→ dim_log (incl. events not in the alert)"),
            ("alert_id", "N", "→ fact_alert (nullable)"),
            ("technique_id", "N", "→ dim_mitre"),
            ("user_key / hostname", "N", "→ dim_user / dim_vulnerability"),
            ("context_key", "N", "→ dim_context"),
            ("evidence_origin", "N", "alert / hidden log / context"),
            ("description", "N", "what happened"),
            ("confidence", "M", "0–1"),
        ],
    ),
    "dim_mitre": (
        "MITRE ATT&CK Enterprise (STIX) + catalog + sandbox",
        MIT,
        [
            ("technique_id", "PK", "T1566.002"),
            ("technique / sub_technique", "A", ""),
            ("parent_technique_id", "A", "T1566"),
            ("tactic / tactic_id", "A", "TA0001 …"),
            ("kill_chain_order", "A", "1–14 (sequencing)"),
            ("data_sources", "A", "which logs to query"),
            ("mitigations", "A", "Mxxxx → containment"),
        ],
    ),
    "dim_rule": (
        "catalogo_casos_de_uso.csv + runbooks",
        "#7d8b12",
        [
            ("rule_id", "PK", ""),
            ("nombre / fuente", "A", ""),
            ("severidad_base", "A", "matrix row"),
            ("tecnica_id", "A", "→ dim_mitre"),
            ("runbook / runbook_checks", "A", "investigation plan"),
        ],
    ),
    "dim_user": (
        "usuarios.csv + eventos_rrhh.csv",
        "#1f5f9e",
        [
            ("user_key", "PK", "lower(username)"),
            ("upn / username", "A", ""),
            ("department / title", "A", ""),
            ("account_type", "A", ""),
            ("privileged / vip", "A", "+1 severity"),
            ("mfa_method / status", "A", ""),
            ("hr_event / fecha_efectiva", "A", "leaver, role change"),
        ],
    ),
    "dim_vulnerability": (
        "vulnerabilidades + activos + servicios_negocio",
        "#2e7d32",
        [
            ("hostname", "PK", ""),
            ("criticality", "A", "matrix column"),
            ("business_service / criticidad", "A", "isolation approver"),
            ("zone / internet_facing", "A", "incl. OT"),
            ("edr_installed", "A", ""),
            ("cve_id / severidad_cvss / estado", "A", "exploitable path"),
        ],
    ),
    "dim_context": (
        "ti_feed + geoip_asn + sandbox + calendario_cambios",
        "#b8860b",
        [
            ("context_key", "PK", "IOC value or change id"),
            ("context_type", "A", "ioc / ip / file / change"),
            ("reputation / confidence", "A", "unknown ≠ clean"),
            ("malware_family / tags", "A", ""),
            ("country / asn / is_tor / is_hosting", "A", "GeoIP"),
            ("sandbox_verdict / sandbox_mitre", "A", "→ dim_mitre"),
            ("change_window / scope", "A", "authorised activity"),
        ],
    ),
    "dim_log": (
        "unified view · 18 sources · 814k events",
        "#3b6fb6",
        [
            ("event_id", "PK", "prefix = source"),
            ("source / timestamp", "A", "UTC"),
            ("user_key / hostname", "A", "normalised"),
            ("src_ip / dst", "A", "IP, domain, URL"),
            ("action / result", "A", ""),
            ("sha256", "A", ""),
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
    "N": ("#e3f4ef", "+"),
}


def port(c):
    return "p" + "".join(ch if ch.isalnum() else "_" for ch in c)


def node(name, sub, head, cols, pos):
    big = name.startswith(("fact", "bridge"))
    r = [
        f'<TR><TD COLSPAN="3" BGCOLOR="{head}"><FONT COLOR="white" POINT-SIZE="{18 if big else 16}"><B>{name}</B></FONT></TD></TR>',
        f'<TR><TD COLSPAN="3" BGCOLOR="{head}"><FONT COLOR="white" POINT-SIZE="10">{html.escape(sub)}</FONT></TD></TR>',
    ]
    for c, t, note in cols:
        bg, lab = TAG[t]
        b = ("<B>", "</B>") if t in ("PK", "FK") else ("", "")
        r.append(
            f'<TR><TD BGCOLOR="{bg}" WIDTH="26" PORT="{port(c)}_l"><FONT POINT-SIZE="10">{lab}</FONT></TD>'
            f'<TD ALIGN="LEFT" BGCOLOR="{bg}" PORT="{port(c)}"><FONT POINT-SIZE="12">{b[0]}{html.escape(c)}{b[1]}</FONT></TD>'
            f'<TD ALIGN="LEFT" BGCOLOR="{bg}" PORT="{port(c)}_r"><FONT POINT-SIZE="10" COLOR="#555555">{html.escape(note) or "&#160;"}</FONT></TD></TR>'
        )
    return f'"{name}" [pos="{pos[0]},{pos[1]}!", label=<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">{"".join(r)}</TABLE>>];'


POS = {
    "dim_user": (-13, 8.6),
    "dim_vulnerability": (-4.3, 8.6),
    "dim_context": (4.6, 8.6),
    "dim_rule": (-13, 0.3),
    "fact_alert": (-4.3, 0),
    "bridge_alert_incident": (4.6, 1.6),
    "fact_incident": (13.6, 0),
    "dim_log": (-13, -8.6),
    "dim_mitre": (-4.3, -8.6),
    "fact_attack_step": (5.4, -8.9),
    "legend": (14.2, 9.0),
}
g = [
    "graph G {",
    'graph [layout=neato, splines=true, overlap=false, pad=0.6, fontname="Helvetica", forcelabels=true,',
    ' label=<<FONT POINT-SIZE="30"><B>Tarvia SOC — Star-join schema v2: triage, correlation and attack-chain reconstruction</B></FONT><BR/>'
    '<FONT POINT-SIZE="15"><FONT COLOR="#c0392b"><B>L1</B> alert triage</FONT> · <FONT COLOR="#6c3483"><B>L2</B> correlation of similar alerts → incident</FONT> · '
    '<FONT COLOR="#0e6655"><B>L3</B> attack-chain reconstruction</FONT> · <FONT COLOR="#34495e"><B>MITRE ATT&amp;CK</B> shared dimension</FONT> · green rows (+) = new in v2</FONT>>, labelloc=t];',
    'node [shape=plaintext, fontname="Helvetica"]; edge [penwidth=2.4, fontname="Helvetica", fontsize=12];',
]
for n, (sub, head, cols) in T.items():
    g.append(node(n, sub, head, cols, POS[n]))


def E(a, ac, aside, b, bc, bside, color, lab, style="solid"):
    sa = "_l" if aside == "w" else ("_r" if aside == "e" else "")
    sb = "_l" if bside == "w" else ("_r" if bside == "e" else "")
    pa = f'"{a}":{port(ac)}{sa}:{aside}' if ac else f'"{a}":{aside}'
    pb = f'"{b}":{port(bc)}{sb}:{bside}' if bc else f'"{b}":{bside}'
    g.append(f'{pa} -- {pb} [color="{color}", fontcolor="{color}", xlabel="{lab}", style={style}];')


# L1 star
E("fact_alert", "rule_id", "w", "dim_rule", "rule_id", "e", "#7d8b12", "rule_id (N:1)")
E("fact_alert", "user_key", "w", "dim_user", None, "s", "#1f5f9e", "user_key (N:1)")
E("fact_alert", None, "n", "dim_vulnerability", None, "s", "#2e7d32", "hostname (N:1)")
E("fact_alert", "context_key", "e", "dim_context", None, "s", "#b8860b", "context_key (N:M)")
E("fact_alert", "event_id", "w", "dim_log", None, "n", "#3b6fb6", "event_id (N:M)")
E("fact_alert", None, "s", "dim_mitre", None, "n", MIT, "technique_id (N:1)")
# L2
E("fact_alert", "alert_id", "e", "bridge_alert_incident", "alert_id", "w", L2, "alert_id (1:N)")
E("bridge_alert_incident", "incident_id", "e", "fact_incident", "incident_id", "w", L2, "incident_id (N:1)")
# L3
E("fact_incident", None, "s", "fact_attack_step", "incident_id", "e", L3, "incident_id (1:N)")
E("fact_attack_step", "technique_id", "w", "dim_mitre", "technique_id", "e", MIT, "technique_id (N:1)")
E("fact_attack_step", "event_id", "w", "dim_log", None, "s", "#3b6fb6", "event_id (N:1)", "dashed")
E("fact_alert", "action", "e", "fact_attack_step", None, "n", L1, "alert_id (0..1)", "dashed")

g.append(
    'legend [pos="14.2,9.0!", label=<<TABLE BORDER="1" CELLBORDER="0" CELLSPACING="2" CELLPADDING="3" BGCOLOR="#fafafa">'
    '<TR><TD COLSPAN="2"><B>Legend</B></TD></TR>'
    '<TR><TD BGCOLOR="#fff2cc">PK</TD><TD ALIGN="LEFT">Primary key</TD></TR>'
    '<TR><TD BGCOLOR="#e8f0fe">FK</TD><TD ALIGN="LEFT">Foreign key (v1)</TD></TR>'
    '<TR><TD BGCOLOR="#e3f4ef">+</TD><TD ALIGN="LEFT">New in v2 (L2 / L3 / MITRE)</TD></TR>'
    '<TR><TD BGCOLOR="#efe3f7">M</TD><TD ALIGN="LEFT">Output computed by the system</TD></TR>'
    '<TR><TD BGCOLOR="#fde2e2">{ }</TD><TD ALIGN="LEFT">JSON / attacker-controllable</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT">Dashed edge = secondary link</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT"><B>Flow</B>: alert (L1) → bridge (L2)</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT">→ incident → attack steps (L3),</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT">ordered by dim_mitre.kill_chain_order</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT">and timestamp; dim_context removes</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT">authorised activity before chaining</TD></TR>'
    "</TABLE>>];"
)
g.append("}")
dot = OUT / "star_schema_v2_levels.dot"
dot.write_text("\n".join(g), encoding="utf-8")
subprocess.run(["neato", "-Tpng", "-Gdpi=120", str(dot), "-o", str(OUT / "star_schema_v2_levels.png")], check=True)
subprocess.run(["neato", "-Tsvg", str(dot), "-o", str(OUT / "star_schema_v2_levels.svg")], check=True)
print("ok")
