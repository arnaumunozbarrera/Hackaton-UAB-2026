"""Command line: `serve` starts the chat UI, `triage` runs one alert and prints the validated ticket.

Why: lets the team try the LLM stage without the database and without writing code.
"""

from __future__ import annotations

import argparse
import json
import sys

from .client import load_env
from .server import App, serve


def main(argv: list[str] | None = None) -> int:
    load_env()
    p = argparse.ArgumentParser(prog="python -m src.llm_triage", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="chat web local")
    s.add_argument("--port", type=int, default=8765)
    t = sub.add_parser("triage", help="triaje de una alerta por consola")
    t.add_argument("alert_id")
    t.add_argument("--note", default="", help="indicación del analista")
    for sp in (s, t):
        sp.add_argument("--data", default="docs")
        mode = sp.add_mutually_exclusive_group()
        mode.add_argument("--mock", action="store_true", help="sin LLM (respuesta simulada)")
        mode.add_argument("--claude-code", action="store_true", help="CLI local de Claude Code con tu sesión del plan")
        sp.add_argument("--model", default=None, help="modelo (API: TARVIA_LLM_MODEL; Claude Code: sonnet, opus...)")
    args = p.parse_args(argv)
    mode = "mock" if args.mock else "claude-code" if args.claude_code else "anthropic"
    app = App(args.data, mode, args.model)
    if args.cmd == "serve":
        serve(app, args.port)
        return 0
    out = app.triage(args.alert_id, args.note)["result"]
    print(json.dumps(out, ensure_ascii=False, indent=1, default=str))
    return 0 if out["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
