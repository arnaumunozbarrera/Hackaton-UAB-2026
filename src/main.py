"""Tarvia SOC triage workflow. Run from the repository root: python -m src.main

    sync (SOC API) -> enrich -> log selection -> embeddings -> discriminator | prompt + LLM -> triage_tickets

Examples:
    python -m src.main --limit 50                    # mock LLM, triage the 50 most severe pending alerts
    python -m src.main --mode claude-code --limit 10 # local Claude Code with your plan session
    python -m src.main --no-sync --alert ALR-20261005-000172 --mode anthropic
"""

from __future__ import annotations

import argparse
import json

import requests

from .llm_triage.client import load_env
from .triage_flow import TriageFlow
from .triage_flow.flow import MODES


def main(argv: list[str] | None = None) -> int:
    load_env()
    parser = argparse.ArgumentParser(prog="python -m src.main", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)  # fmt: skip
    parser.add_argument("--db", default=None, help="SQLite path (default TARVIA_DB or data/tarvia.sqlite)")
    parser.add_argument("--data", default="docs")
    parser.add_argument("--mode", choices=MODES, default="mock")
    parser.add_argument("--model", default=None)
    parser.add_argument("--no-sync", action="store_true", help="skip the SOC API ingestion")
    parser.add_argument("--limit", type=int, default=20, help="pending alerts to triage (0 = none, -1 = all)")
    parser.add_argument("--alert", action="append", default=[], help="triage these alert ids (repeatable)")
    args = parser.parse_args(argv)

    flow = TriageFlow(args.db, args.data, args.mode, args.model)
    try:
        if not args.no_sync:
            try:
                print(json.dumps(flow.sync()["sync"], ensure_ascii=False))
            except requests.RequestException as exc:
                print(f"[main] SOC API not reachable ({type(exc).__name__}); continuing with the stored alerts")
        if args.alert:
            summary = flow.run_batch(alert_ids=args.alert)
        elif args.limit:
            summary = flow.run_batch(limit=None if args.limit < 0 else args.limit)
        else:
            summary = {"processed": 0}
        print(json.dumps(summary, ensure_ascii=False))
    finally:
        flow.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
