"""Command line: reconstruct the attack chain of one alert that already has a triage ticket and store it."""

from __future__ import annotations

import argparse
import json
import sys

from ..database import enrich
from ..llm_triage.client import load_env
from . import store
from .catalogue import InvestigationBackend
from .runner import ChainRunner


def main(argv: list[str] | None = None) -> int:
    load_env()
    p = argparse.ArgumentParser(prog="python -m src.investigation", description=__doc__)
    p.add_argument("alert_id")
    p.add_argument("--db", default=None, help="SQLite (por defecto TARVIA_DB o data/tarvia.sqlite)")
    p.add_argument("--data", default="docs")
    p.add_argument("--model", default=None)
    p.add_argument("--no-save", action="store_true", help="no guardar el informe en attack_chains")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--mock", action="store_true")
    mode.add_argument("--claude-code", action="store_true")
    args = p.parse_args(argv)
    db = enrich.db_path(args.db)
    runner = ChainRunner(InvestigationBackend(db), args.data)
    result = runner.run(args.alert_id, mode="mock" if args.mock else "claude-code" if args.claude_code else "anthropic",
                        model=args.model).to_dict()  # fmt: skip
    if not args.no_save:
        conn = enrich.connect(db)
        store.ensure(conn)
        store.save(conn, result, "cli")
        conn.close()
    print(json.dumps(result, ensure_ascii=False, indent=1, default=str))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
