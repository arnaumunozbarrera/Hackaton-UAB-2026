"""Render lightweight PNG architecture diagrams without requiring Graphviz."""

from pathlib import Path
from textwrap import wrap

from PIL import Image, ImageDraw, ImageFont


OUT = Path(__file__).parent
FONT_CANDIDATES = [
    Path("C:/Windows/Fonts/segoeui.ttf"),
    Path("C:/Windows/Fonts/arial.ttf"),
]


def font(size, bold=False):
    candidates = [
        Path("C:/Windows/Fonts/segoeuib.ttf") if bold else None,
        Path("C:/Windows/Fonts/arialbd.ttf") if bold else None,
        *FONT_CANDIDATES,
    ]
    for path in candidates:
        if path and path.exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


TITLE = font(34, True)
SUBTITLE = font(17)
HEAD = font(20, True)
BODY = font(16)
SMALL = font(14)


def centered(draw, xy, text, fnt, fill):
    box = draw.multiline_textbbox((0, 0), text, font=fnt, spacing=4, align="center")
    draw.multiline_text((xy[0] - (box[2] - box[0]) / 2, xy[1] - (box[3] - box[1]) / 2), text, font=fnt, fill=fill, spacing=4, align="center")


def box(draw, xy, size, title, body, color, text_color="#17202a"):
    x, y = xy
    w, h = size
    draw.rounded_rectangle((x, y, x + w, y + h), radius=16, fill="#ffffff", outline=color, width=4)
    draw.rounded_rectangle((x, y, x + w, y + 44), radius=16, fill=color)
    draw.rectangle((x, y + 28, x + w, y + 44), fill=color)
    centered(draw, (x + w / 2, y + 22), title, HEAD, "#ffffff")
    lines = []
    for paragraph in body.split("\n"):
        lines.extend(wrap(paragraph, max(18, int(w / 11))))
    draw.multiline_text((x + 16, y + 58), "\n".join(lines), font=BODY, fill=text_color, spacing=7)


def arrow(draw, start, end, color="#566573", width=4):
    draw.line((*start, *end), fill=color, width=width)
    x1, y1 = start
    x2, y2 = end
    if abs(x2 - x1) >= abs(y2 - y1):
        direction = 1 if x2 >= x1 else -1
        points = [(x2, y2), (x2 - direction * 15, y2 - 8), (x2 - direction * 15, y2 + 8)]
    else:
        direction = 1 if y2 >= y1 else -1
        points = [(x2, y2), (x2 - 8, y2 - direction * 15), (x2 + 8, y2 - direction * 15)]
    draw.polygon(points, fill=color)


def overview():
    image = Image.new("RGB", (1900, 1180), "#f5f7fa")
    draw = ImageDraw.Draw(image)
    centered(draw, (950, 42), "Tarvia SOC — Build star schema overview", TITLE, "#17202a")
    centered(draw, (950, 82), "Raw source files → normalized hybrid database → triage, correlation and attack-chain reconstruction", SUBTITLE, "#566573")

    box(draw, (55, 155), (300, 300), "1 · INPUT", "CSV / JSONL\n\nInventory, alerts, 18 log sources, threat intelligence, changes and runbooks\n\nOriginal bytes are preserved", "#2874a6")
    box(draw, (420, 155), (350, 300), "2 · BASE LAYER", "archivo_fuente\ndocumento\nusuario · activo · cambio\nregla · alerta\nevento · indicador\ninteligencia · geoip · sandbox", "#1f618d")
    box(draw, (835, 155), (350, 300), "3 · NORMALIZATION", "Shortcut columns for joins:\n\nuser_key · hostname · IPs\naction · result · destination\n\nparticipacion and ocurrencia_indicador preserve relationships", "#148f77")
    box(draw, (1250, 155), (560, 300), "4 · STAR / HYBRID DATABASE", "Dimensions: dim_user, dim_vulnerability, dim_context, dim_rule, dim_mitre, dim_log\n\nFacts: fact_alert, fact_incident, fact_attack_step\n\nBridges: alert↔event, alert↔entity, alert↔incident", "#117864")

    arrow(draw, (355, 305), (420, 305), "#2874a6")
    arrow(draw, (770, 305), (835, 305), "#1f618d")
    arrow(draw, (1185, 305), (1250, 305), "#148f77")

    draw.rounded_rectangle((55, 545, 1810, 1035), radius=20, fill="#ffffff", outline="#d5d8dc", width=2)
    centered(draw, (933, 580), "Processing layers", HEAD, "#17202a")

    box(draw, (105, 650), (460, 285), "L1 · TRIAGE", "fact_alert\n\nResolve users, hosts, indicators and related events.\n\nApply severity matrix and retain the original alert evidence.", "#c0392b")
    box(draw, (720, 650), (460, 285), "L2 · CORRELATION", "resultado_alerta\nbridge_alert_incident\nfact_incident\n\nGroup related alerts by shared entities, time windows, duplicate hashes and authorised changes.", "#6c3483")
    box(draw, (1335, 650), (380, 285), "L3 · RECONSTRUCTION", "fact_attack_step\n\nOrder evidence chronologically and by MITRE kill-chain stage.\n\nProduce an investigation report.", "#0e6655")
    arrow(draw, (565, 792), (720, 792), "#7b7d7d")
    arrow(draw, (1180, 792), (1335, 792), "#7b7d7d")
    draw.text((78, 1080), "Pattern filtering is an optional catalog-driven branch over dim_log/evento; raw evidence remains available.", font=SMALL, fill="#566573")
    image.save(OUT / "build_star_schema_overview.png", optimize=True)


def filtering():
    image = Image.new("RGB", (1900, 1150), "#f5f7fa")
    draw = ImageDraw.Draw(image)
    centered(draw, (950, 42), "Cross-product detection, pattern matching and filtering", TITLE, "#17202a")
    centered(draw, (950, 82), "Identify repeated activity across products, review reusable patterns, then reduce triage noise without deleting evidence", SUBTITLE, "#566573")

    box(draw, (60, 175), (385, 420), "A · evento / dim_log", "Raw normalized event\n\nsource product\ntimestamp\naction · result\nuser · hostname\nsource / destination IP\nref_id · detail\n\nAll original detail remains in datos_json.", "#2874a6")
    box(draw, (520, 175), (390, 420), "B · CANDIDATE VIEW", "v_common_log_candidates\n\nGroups action + result and keeps only combinations observed in more than one product.\n\nUseful for discovering common operational behavior before approving a pattern.", "#148f77")
    box(draw, (990, 175), (390, 420), "C · common_log_pattern", "Reusable reviewed catalog\n\npattern_name\nsource_product / action / result\nnormalized_fingerprint\nclassification\nfiltering_action\nconfidence · rationale\nenabled", "#a04000")
    box(draw, (1460, 175), (380, 420), "D · MATCH", "log_pattern_match\n\nLinks event_id ↔ pattern_id\n\nmatched_by:\nfingerprint · fields · analyst\n\nmatch_confidence\n\nThe decision is auditable.", "#a04000")
    arrow(draw, (445, 385), (520, 385), "#2874a6")
    arrow(draw, (910, 385), (990, 385), "#148f77")
    arrow(draw, (1380, 385), (1460, 385), "#a04000")

    draw.rounded_rectangle((60, 700, 1840, 1030), radius=20, fill="#ffffff", outline="#d5d8dc", width=2)
    centered(draw, (950, 735), "Filtering outcomes", HEAD, "#17202a")
    box(draw, (115, 790), (460, 180), "retain", "Keep visible in normal triage.\nUse when the pattern is only a correlation hint.", "#5d6d7e")
    box(draw, (720, 790), (460, 180), "aggregate", "Collapse repeated events for analyst views.\nKeep the underlying rows for investigation.", "#b9770e")
    box(draw, (1325, 790), (400, 180), "hide_from_triage", "Exclude from v_useful_logs.\nNever delete evento or its raw detail.", "#922b21")
    draw.text((75, 1080), "Safety rule: only enabled, reviewed patterns can change triage visibility; the original evidence remains queryable.", font=SMALL, fill="#566573")
    image.save(OUT / "cross_product_log_filtering.png", optimize=True)


if __name__ == "__main__":
    overview()
    filtering()
    print("PNG diagrams written")
