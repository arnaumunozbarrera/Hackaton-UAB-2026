"""Generates the Tarvia SOC star-schema diagram (DOT -> PNG)."""

import html
import pathlib
import subprocess

OUT = pathlib.Path(__file__).parent

# colors per conformed dimension (edges + key cells)
C = {
    "user": "#1f77b4",
    "asset": "#2ca02c",
    "ip": "#d62728",
    "ind": "#9467bd",
    "file": "#8c564b",
    "cust": "#e377c2",
    "zone": "#7f7f7f",
    "svc": "#17becf",
    "rule": "#bcbd22",
    "rb": "#ff7f0e",
    "date": "#555555",
}
DIM_PK = {
    "user": ("dim_user", "user_key"),
    "asset": ("dim_asset", "hostname"),
    "ip": ("dim_ip", "ip"),
    "ind": ("dim_indicator", "value"),
    "file": ("dim_file", "sha256"),
    "cust": ("dim_customer", "customer_id"),
    "zone": ("dim_zone", "zona"),
    "svc": ("dim_service", "servicio"),
    "rule": ("dim_rule", "rule_id"),
    "rb": ("dim_runbook", "runbook_id"),
}

# table: (title, subtitle, header color, [ (column, tag, fk_dim) ])  tag: PK / NK / FK / J (json) / U (untrusted text) / ""
LOGS = {
    "Identity": {
        "idp_signins": (
            "76,713 · SIGN-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("user_upn", "FK", "user"),
                ("app", "", None),
                ("result", "", None),
                ("failure_reason", "", None),
                ("mfa_method", "", None),
                ("mfa_result", "", None),
                ("src_ip", "FK", "ip"),
                ("country", "", None),
                ("city", "", None),
                ("asn", "", None),
                ("user_agent", "", None),
                ("device_id", "", None),
                ("device_compliant", "", None),
                ("session_id", "", None),
                ("risk_level", "", None),
                ("conditional_access", "", None),
            ],
        ),
        "idp_audit": (
            "762 · AUD-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("actor_upn", "FK", "user"),
                ("operation", "", None),
                ("target", "", None),
                ("src_ip", "FK", "ip"),
                ("details{app,rule_name,conditions,...}", "J", None),
            ],
        ),
        "ad_events": (
            "526 · ADE-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("dc", "FK", "asset"),
                ("event_code", "", None),
                ("event", "", None),
                ("subject", "FK", "user"),
                ("target", "FK", "user"),
                ("src_host", "FK", "asset"),
                ("details{group,description,...}", "J", None),
            ],
        ),
        "vpn": (
            "9,821 · VPN-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("user", "FK", "user"),
                ("src_ip", "FK", "ip"),
                ("assigned_ip", "", None),
                ("action", "", None),
                ("country", "", None),
                ("bytes", "", None),
                ("mfa_result", "", None),
            ],
        ),
    },
    "Endpoint": {
        "edr_events": (
            "112,492 · EDR-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("event_type", "", None),
                ("hostname", "FK", "asset"),
                ("user (TARVIA\\u)", "FK", "user"),
                ("process_name", "", None),
                ("process_path", "", None),
                ("command_line", "U", None),
                ("parent_name", "", None),
                ("pid / parent_pid", "", None),
                ("sha256", "FK", "file"),
                ("signer", "", None),
                ("integrity", "", None),
                ("details{decoded,detection,action}", "J", None),
            ],
        ),
        "dlp": (
            "1,042 · DLP-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("user", "FK", "user"),
                ("hostname", "FK", "asset"),
                ("channel", "", None),
                ("destination", "FK", "ind"),
                ("file_name", "", None),
                ("file_size", "", None),
                ("policy", "", None),
                ("action", "", None),
                ("matches{dni_nie,iban,email,phone}", "J", None),
            ],
        ),
    },
    "Network": {
        "proxy": (
            "194,258 · PRX-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("src_ip", "", None),
                ("hostname", "FK", "asset"),
                ("user", "FK", "user"),
                ("method", "", None),
                ("url", "", None),
                ("domain", "FK", "ind"),
                ("dst_ip", "FK", "ip"),
                ("status", "", None),
                ("bytes_out / bytes_in", "", None),
                ("category", "", None),
                ("action", "", None),
                ("user_agent", "", None),
            ],
        ),
        "dns": (
            "178,221 · DNS-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("src_ip", "", None),
                ("hostname", "FK", "asset"),
                ("query", "FK", "ind"),
                ("qtype", "", None),
                ("response", "", None),
                ("rcode", "", None),
            ],
        ),
        "firewall": (
            "24,648 · FW-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("src_ip", "FK", "ip"),
                ("src_port", "", None),
                ("dst_ip", "FK", "ip"),
                ("dst_port", "", None),
                ("proto", "", None),
                ("action", "", None),
                ("rule", "", None),
                ("bytes", "", None),
                ("zone_src", "FK", "zone"),
                ("zone_dst", "FK", "zone"),
            ],
        ),
    },
    "Email": {
        "email": (
            "56,797 · EML-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("direction", "", None),
                ("message_id", "NK", None),
                ("sender", "FK", "ind"),
                ("recipients[ ]", "FK", "user"),
                ("subject", "U", None),
                ("attachments[ ] (sha256)", "FK", "file"),
                ("urls[ ]", "FK", "ind"),
                ("verdict / action", "", None),
                ("spf / dkim / dmarc", "", None),
                ("sender_ip", "FK", "ip"),
            ],
        ),
        "email_clicks": (
            "16,249 · CLK-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("user", "FK", "user"),
                ("url", "FK", "ind"),
                ("message_id", "FK", None),
                ("action", "", None),
                ("verdict_at_click", "", None),
                ("src_ip", "FK", "ip"),
            ],
        ),
    },
    "Customer-facing (web, e-com, AI)": {
        "waf": (
            "71,421 · WAF-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("src_ip", "FK", "ip"),
                ("country", "", None),
                ("method", "", None),
                ("host", "FK", "svc"),
                ("uri", "U", None),
                ("status", "", None),
                ("rule_id / rule_msg", "", None),
                ("action", "", None),
                ("user_agent", "", None),
                ("bytes", "", None),
            ],
        ),
        "ecom_auth": (
            "44,064 · ECA-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("customer_id", "FK", "cust"),
                ("email", "", None),
                ("src_ip", "FK", "ip"),
                ("result", "", None),
                ("failure_reason", "", None),
                ("user_agent", "", None),
                ("device_fp", "", None),
                ("captcha", "", None),
            ],
        ),
        "ecom_account": (
            "7,661 · ECO-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("customer_id", "FK", "cust"),
                ("event", "", None),
                ("src_ip", "FK", "ip"),
                ("amount", "", None),
                ("details{order,payment,giftcard,...}", "J", None),
            ],
        ),
        "ai_gateway": (
            "8,817 · AIG-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("session_id", "", None),
                ("customer_id", "FK", "cust"),
                ("authenticated", "", None),
                ("src_ip", "FK", "ip"),
                ("prompt", "U", None),
                ("response_summary", "", None),
                ("tool_calls", "J", None),
                ("guardrail{triggered,category,action}", "J", None),
                ("model / tokens_in / tokens_out", "", None),
            ],
        ),
    },
    "Cloud, data & DevOps": {
        "cloudtrail": (
            "6,496 · CT-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("eventName / eventSource", "", None),
                ("awsRegion", "", None),
                ("sourceIPAddress", "FK", "ip"),
                ("userAgent", "", None),
                ("userIdentity.userName", "FK", "user"),
                ("userIdentity.accessKeyId", "", None),
                ("errorCode", "", None),
                ("requestParameters{bucket,policy,key}", "J", None),
                ("bytes_transferred", "", None),
            ],
        ),
        "sql_audit": (
            "3,924 · SQL-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("user", "FK", "user"),
                ("client_host", "FK", "asset"),
                ("database", "", None),
                ("statement_type", "", None),
                ("object", "", None),
                ("rows_returned", "", None),
                ("statement", "", None),
            ],
        ),
        "cicd_builds": (
            "559 · CI-*",
            [
                ("event_id", "PK", None),
                ("timestamp", "", None),
                ("pipeline", "", None),
                ("build_id", "", None),
                ("runner", "", None),
                ("step", "", None),
                ("status", "", None),
                ("details{new_packages,env_read,network,author}", "J", None),
            ],
        ),
    },
}

DIMS = {
    "dim_user": (
        "usuarios.csv · 1,224",
        [
            ("user_key", "PK", None),
            ("user_id", "NK", None),
            ("username", "NK", None),
            ("upn", "NK", None),
            ("display_name", "", None),
            ("department / title", "", None),
            ("location", "", None),
            ("manager_upn", "FK", "user"),
            ("account_type", "", None),
            ("privileged", "", None),
            ("vip", "", None),
            ("mfa_method", "", None),
            ("status / created", "", None),
            ("workstation", "FK", "asset"),
            ("notes", "", None),
        ],
    ),
    "dim_asset": (
        "activos.csv · 1,185",
        [
            ("hostname", "PK", None),
            ("asset_id", "NK", None),
            ("ip", "", None),
            ("type / os", "", None),
            ("criticality", "", None),
            ("zone", "FK", "zone"),
            ("location", "", None),
            ("business_service", "FK", "svc"),
            ("owner_upn", "FK", "user"),
            ("internet_facing", "", None),
            ("edr_installed", "", None),
            ("description", "", None),
        ],
    ),
    "dim_service": (
        "servicios_negocio.csv",
        [
            ("servicio", "PK", None),
            ("criticidad", "", None),
            ("impacto", "", None),
            ("activos (list)", "", None),
            ("responsable", "", None),
        ],
    ),
    "dim_zone": (
        "zonas_red.csv + tiendas.csv",
        [
            ("zona", "PK", None),
            ("cidr", "", None),
            ("ubicacion", "", None),
            ("descripcion", "", None),
            ("tienda / nombre / ciudad", "", None),
        ],
    ),
    "dim_ip": (
        "geoip_asn.csv (+ CIDR→zone)",
        [
            ("ip", "PK", None),
            ("country / city", "", None),
            ("asn / as_org", "", None),
            ("is_tor", "", None),
            ("is_vpn_provider", "", None),
            ("is_hosting", "", None),
            ("is_residential_proxy", "", None),
            ("internal_zone (derived)", "FK", "zone"),
        ],
    ),
    "dim_indicator": (
        "ti_feed.jsonl (TIP)",
        [
            ("value", "PK", None),
            ("indicator_type", "", None),
            ("reputation", "", None),
            ("confidence", "", None),
            ("malware_family", "", None),
            ("tags", "", None),
            ("first_seen / last_seen", "", None),
            ("source", "", None),
            ("note", "", None),
        ],
    ),
    "dim_file": (
        "sandbox_informes.jsonl",
        [
            ("sha256", "PK", None),
            ("md5", "", None),
            ("file_name", "", None),
            ("verdict", "", None),
            ("score", "", None),
            ("malware_family", "", None),
            ("behaviors", "J", None),
            ("network{domains,ips,urls}", "J", None),
            ("mitre", "", None),
            ("dropped_files", "", None),
            ("analyzed_at", "", None),
        ],
    ),
    "dim_customer": ("derived from ecom_* / ai_gateway", [("customer_id", "PK", None), ("email", "", None)]),
    "dim_date": (
        "derived from timestamps",
        [
            ("ts_utc", "PK", None),
            ("ts_madrid (UTC+2/+1)", "", None),
            ("date / hour", "", None),
            ("business_hours", "", None),
        ],
    ),
}
CONTEXT = {
    "fact_change": (
        "calendario_cambios.csv",
        [
            ("id", "PK", None),
            ("titulo", "", None),
            ("inicio / fin", "", None),
            ("solicitante", "", None),
            ("detalle (IPs, scope)", "", None),
            ("alcance", "FK", "asset"),
        ],
    ),
    "fact_hr_event": (
        "eventos_rrhh.csv",
        [
            ("fecha", "", None),
            ("tipo", "", None),
            ("usuario", "FK", "user"),
            ("detalle", "", None),
            ("fecha_efectiva", "", None),
        ],
    ),
    "fact_vulnerability": (
        "vulnerabilidades.csv",
        [
            ("hostname", "FK", "asset"),
            ("id (CVE)", "PK", None),
            ("producto", "", None),
            ("severidad_cvss", "", None),
            ("estado", "", None),
            ("detectada", "", None),
            ("notas", "", None),
        ],
    ),
}
ALERTS = {
    "fact_alert": (
        "alertas.jsonl · 11,061",
        [
            ("alert_id", "PK", None),
            ("created_at", "FK", "date"),
            ("source_product", "", None),
            ("rule_id", "FK", "rule"),
            ("rule_name", "", None),
            ("severity (rule)", "", None),
            ("status", "", None),
            ("mitre_tactic / technique_id", "", None),
            ("description", "", None),
            ("runbook", "FK", "rb"),
            ("entities{users,hosts,ips,...}", "J", None),
            ("evidence{...} (≈140 keys)", "U", None),
        ],
    ),
    "bridge_alert_entity": (
        "derived from entities{}",
        [
            ("alert_id", "FK", None),
            ("entity_type", "", None),
            ("entity_value", "", None),
            ("entity_key (→ user/asset/ip/ind/file/cust)", "FK", None),
        ],
    ),
    "bridge_alert_event": (
        "derived from related_events[]",
        [("alert_id", "FK", None), ("event_id", "FK", None), ("source (prefix → log table)", "", None)],
    ),
    "dim_rule": (
        "catalogo_casos_de_uso.csv · 44",
        [
            ("rule_id", "PK", None),
            ("nombre", "", None),
            ("fuente", "", None),
            ("severidad_base", "", None),
            ("tactica / tecnica_id", "", None),
            ("runbook", "FK", "rb"),
            ("logica", "", None),
        ],
    ),
    "dim_runbook": (
        "runbooks/RB-01..10.md",
        [("runbook_id", "PK", None), ("reglas", "", None), ("comprobaciones", "", None), ("decision", "", None)],
    ),
    "fact_ticket": (
        "system output · ticket_salida.schema",
        [
            ("ticket_id", "PK", None),
            ("alert_ids[ ]", "FK", None),
            ("title", "", None),
            ("verdict", "", None),
            ("confidence", "", None),
            ("severity (final)", "", None),
            ("severity_rationale", "", None),
            ("affected{users,hosts,services}", "J", None),
            ("summary / evidence", "", None),
            ("recommended_actions", "", None),
            ("escalation", "", None),
        ],
    ),
}

TAG_STYLE = {
    "PK": ("#fff2cc", "PK"),
    "NK": ("#fff9e6", "NK"),
    "FK": ("#e8f0fe", "FK"),
    "J": ("#f3f3f3", "{ }"),
    "U": ("#fde2e2", "!"),
    "": ("#ffffff", "&#160;"),
}


def port(col):
    return "p" + "".join(ch if ch.isalnum() else "_" for ch in col)


def table(name, sub, cols, head):
    rows = [
        f'<TR><TD COLSPAN="2" BGCOLOR="{head}"><FONT COLOR="white" POINT-SIZE="13"><B>{html.escape(name)}</B></FONT></TD></TR>',
        f'<TR><TD COLSPAN="2" BGCOLOR="{head}"><FONT COLOR="white" POINT-SIZE="9">{html.escape(sub)}</FONT></TD></TR>',
    ]
    for col, tag, fk in cols:
        bg, lab = TAG_STYLE[tag]
        fc = C.get(fk, "#000000") if fk else "#000000"
        b1, b2 = ("<B>", "</B>") if tag in ("PK", "NK") else ("", "")
        rows.append(
            f'<TR><TD BGCOLOR="{bg}" WIDTH="22"><FONT POINT-SIZE="9">{lab}</FONT></TD>'
            f'<TD ALIGN="LEFT" PORT="{port(col)}" BGCOLOR="{bg}"><FONT POINT-SIZE="10" COLOR="{fc}">{b1}{html.escape(col)}{b2}</FONT></TD></TR>'
        )
    return (
        f'"{name}" [label=<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="3">{"".join(rows)}</TABLE>>];'
    )


g = [
    "digraph G {",
    'graph [rankdir=TB, compound=true, nodesep=0.35, ranksep=1.8, newrank=true, splines=true, fontname="Helvetica", bgcolor="white", pad=0.4,',
    ' label=<<FONT POINT-SIZE="26"><B>Tarvia SOC — Analytical data model (star schema)</B></FONT><BR/><FONT POINT-SIZE="13">Top two rows: log fact tables (event grain) · Middle: conformed dimensions + context facts · Bottom: alert fact, bridges and triage output · Edge colour = target dimension</FONT>>, labelloc=t];',
    'node [shape=plaintext, fontname="Helvetica"]; edge [penwidth=1.1, arrowsize=0.6];',
]

# log facts
g.append(
    'subgraph cluster_logs { label=<<B>FACT TABLES — raw logs (04_logs, 814k events)</B>>; style="rounded,filled"; fillcolor="#f5f9ff"; color="#9fb7e0"; fontsize=18;'
)
for i, (grp, tabs) in enumerate(LOGS.items()):
    g.append(
        f'subgraph cluster_l{i} {{ label=<<B>{html.escape(grp)}</B>>; style="rounded,dashed"; color="#9fb7e0"; fontsize=14;'
    )
    for n, (sub, cols) in tabs.items():
        g.append(table(n, sub, cols, "#3b6fb6"))
    g.append("}")
g.append("}")

# dims
g.append(
    'subgraph cluster_dims { label=<<B>DIMENSIONS (02_inventario, 05_inteligencia, derived)</B>>; style="rounded,filled"; fillcolor="#f6fff4"; color="#9fd39a"; fontsize=18;'
)
for n, (sub, cols) in DIMS.items():
    g.append(table(n, sub, cols, "#2e8b57"))
g.append(
    'subgraph cluster_ctx { label=<<B>Context facts (time-bounded, for benign_true_positive)</B>>; style="rounded,dashed"; color="#c9a227"; fontsize=13;'
)
for n, (sub, cols) in CONTEXT.items():
    g.append(table(n, sub, cols, "#b8860b"))
g.append("}}")

# alerts
g.append(
    'subgraph cluster_alerts { label=<<B>ALERT FACT, BRIDGES &amp; TRIAGE OUTPUT</B>>; style="rounded,filled"; fillcolor="#fff6f2"; color="#e0a58c"; fontsize=18;'
)
for n, (sub, cols) in ALERTS.items():
    head = "#c0392b" if n.startswith(("fact", "bridge")) else "#2e8b57"
    if n == "fact_ticket":
        head = "#6c3483"
    g.append(table(n, sub, cols, head))
g.append("}")


def fk_edges(tables, reverse=False):
    for n, (sub, cols) in tables.items():
        for col, tag, fk in cols:
            if not fk or fk == "date":
                continue
            d, pk = DIM_PK[fk]
            if d == n:
                continue
            if reverse:  # draw dim -> fact so the alert side stays on the right
                g.append(f'"{d}":{port(pk)} -> "{n}":{port(col)} [color="{C[fk]}", dir=back, arrowtail=normal];')
            else:
                g.append(f'"{n}":{port(col)} -> "{d}":{port(pk)} [color="{C[fk]}"];')


for grp in LOGS.values():
    fk_edges(grp)
# dim-to-dim / context (drawn without forcing rank)
for n, (sub, cols) in list(DIMS.items()) + list(CONTEXT.items()):
    for col, tag, fk in cols:
        if fk and fk != "date" and DIM_PK[fk][0] != n:
            d, pk = DIM_PK[fk]
            g.append(f'"{n}":{port(col)} -> "{d}":{port(pk)} [color="{C[fk]}", style=dashed, constraint=false];')
fk_edges({k: v for k, v in ALERTS.items() if k in ("fact_alert",)}, reverse=True)
g.append('"dim_rule":prule_id -> "fact_alert":prule_id [color="%s", dir=back, constraint=false];' % C["rule"])
g.append('"dim_runbook":prunbook_id -> "dim_rule":prunbook [color="%s", dir=back, constraint=false];' % C["rb"])
g.append('"dim_runbook":prunbook_id -> "fact_alert":prunbook [color="%s", dir=back, constraint=false];' % C["rb"])
g.append('"fact_alert":palert_id -> "bridge_alert_entity":palert_id [color="#c0392b", penwidth=2];')
g.append('"fact_alert":palert_id -> "bridge_alert_event":palert_id [color="#c0392b", penwidth=2];')
g.append(
    '"fact_alert":palert_id -> "fact_ticket":palert_ids___ [color="#6c3483", penwidth=2, label="N alerts → 1 ticket", fontsize=10];'
)
g.append('"dim_date":pts_utc -> "fact_alert":pcreated_at [color="#555555", style=dotted, dir=back];')
for d, pk in [
    ("dim_user", "user_key"),
    ("dim_asset", "hostname"),
    ("dim_ip", "ip"),
    ("dim_indicator", "value"),
    ("dim_file", "sha256"),
    ("dim_customer", "customer_id"),
]:
    g.append(
        f'"{d}":{port(pk)} -> "bridge_alert_entity":pentity_key____user_asset_ip_ind_file_cust_ [color="#999999", style=dotted, dir=back, constraint=false];'
    )
g.append(
    '"bridge_alert_event":pevent_id -> "idp_signins":pevent_id [color="#c0392b", style=dashed, penwidth=2, lhead=cluster_logs, constraint=false, label="related_events → event_id (any log table, by prefix)", fontcolor="#c0392b", fontsize=12];'
)
g.append(
    '"email_clicks":pmessage_id -> "email":pmessage_id [color="#3b6fb6", style=dashed, constraint=false, label="message_id", fontsize=9];'
)

# row layout
groups = list(LOGS.values())
row1 = [n for gp in groups[:3] for n in gp]
row2 = [n for gp in groups[3:] for n in gp]
row3 = list(DIMS) + list(CONTEXT)
row4 = list(ALERTS) + ["legend"]
for r in (row1, row2, row3, row4):
    g.append("{rank=same; " + " ".join(f'"{n}"' for n in r) + "}")
for a, b in ((row1, row2), (row2, row3), (row3, row4)):
    for x, y in zip(a, b, strict=False):
        g.append(f'"{x}" -> "{y}" [style=invis, weight=5];')
# legend
g.append(
    'legend [label=<<TABLE BORDER="1" CELLBORDER="0" CELLSPACING="2" CELLPADDING="3" BGCOLOR="#fafafa">'
    '<TR><TD COLSPAN="2"><B>Legend</B></TD></TR>'
    '<TR><TD BGCOLOR="#fff2cc">PK</TD><TD ALIGN="LEFT">Primary key</TD></TR>'
    '<TR><TD BGCOLOR="#fff9e6">NK</TD><TD ALIGN="LEFT">Natural / alternate key</TD></TR>'
    '<TR><TD BGCOLOR="#e8f0fe">FK</TD><TD ALIGN="LEFT">Foreign key (text colour = target dimension)</TD></TR>'
    '<TR><TD BGCOLOR="#f3f3f3">{ }</TD><TD ALIGN="LEFT">Nested JSON / array</TD></TR>'
    '<TR><TD BGCOLOR="#fde2e2">!</TD><TD ALIGN="LEFT">Attacker-controllable text (treat as data, never instructions)</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT"><B>Join normalisation</B></TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT">user_key = lower(username); map upn, TARVIA\\user, svc_* to it</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT">Internal IP → dim_zone via CIDR range join; external IP → dim_ip</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT">fact_change / fact_hr_event: join on entity + time window</TD></TR>'
    '<TR><TD COLSPAN="2" ALIGN="LEFT">All timestamps UTC; Madrid = UTC+2 (UTC+1 from 25-Oct)</TD></TR>'
    "</TABLE>>];"
)
g.append("}")

dot = OUT / "data_model_star_schema.dot"
dot.write_text("\n".join(g), encoding="utf-8")
subprocess.run(["dot", "-Tpng", "-Gdpi=110", str(dot), "-o", str(OUT / "data_model_star_schema.png")], check=True)
subprocess.run(["dot", "-Tsvg", str(dot), "-o", str(OUT / "data_model_star_schema.svg")], check=True)
print("ok")
