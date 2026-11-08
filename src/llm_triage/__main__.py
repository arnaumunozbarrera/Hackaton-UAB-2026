"""Command line: `serve` starts the chat UI, `triage` runs one alert and prints the validated ticket.

Why: lets the team try the LLM stage without writing code. With data/tarvia.sqlite present it runs the full
database flow (discriminator, similar alerts, persisted tickets); --dataset keeps the original docs/ mode.
"""

from __future__ import annotations

import argparse
import json
import sys

from .client import load_env
from .server import MODES, App, serve


def main(argv: list[str] | None = None) -> int:
    load_env()
    p = argparse.ArgumentParser(prog="python -m src.llm_triage", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="chat web local")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument(
        "--live",
        type=float,
        default=0,
        metavar="SECONDS",
        help="tiempo real: cada N s ingesta alertas nuevas de la SOC API y las tría (modo base de datos)",
    )
    s.add_argument("--live-batch", type=int, default=3, help="alertas nuevas por ciclo en modo --live")
    s.add_argument(
        "--detail-mode",
        choices=("auto", *MODES),
        default="auto",
        help="LLM al abrir una alerta en el front (auto: el del servidor, o uno real si el servidor va en mock)",
    )
    t = sub.add_parser("triage", help="triaje de una alerta por consola")
    t.add_argument("alert_id")
    t.add_argument("--note", default="", help="indicación del analista")
    for sp in (s, t):
        sp.add_argument("--data", default="docs")
        mode = sp.add_mutually_exclusive_group()
        mode.add_argument("--mock", action="store_true", help="sin LLM (respuesta simulada)")
        mode.add_argument("--claude-code", action="store_true", help="CLI local de Claude Code con tu sesión del plan")
        sp.add_argument("--model", default=None, help="modelo (API: TARVIA_LLM_MODEL; Claude Code: sonnet, opus...)")
        sp.add_argument("--db", default=None, help="SQLite (por defecto TARVIA_DB o data/tarvia.sqlite)")
        sp.add_argument("--dataset", action="store_true", help="forzar el modo dataset (docs/, sin persistencia)")
    args = p.parse_args(argv)
    mode = "mock" if args.mock else "claude-code" if args.claude_code else "anthropic"
    app = App(
        args.data, mode, args.model, db=args.db, dataset=args.dataset, detail_mode=getattr(args, "detail_mode", "auto")
    )
    if args.cmd == "serve" and app.flow is not None:
        print(f"[llm_triage] criterio LLM al abrir una alerta: {app.detail_mode}")
    if args.cmd == "serve":
        if args.live:
            if app.flow is None:
                p.error("--live requiere la base de datos (sin --dataset)")
            app.flow.start_live(args.live, args.live_batch)
            print(
                f"[llm_triage] tiempo real: {args.live_batch} alertas cada {args.live} s desde {app.flow.db_path.name}"
            )
        serve(app, args.port)
        return 0
    out = app.triage(args.alert_id, args.note)["result"]
    print(json.dumps(out, ensure_ascii=False, indent=1, default=str))
    return 0 if out["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
