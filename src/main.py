"""Tarvia SOC triage workflow. Run from the repository root: python -m src.main [--llm mock] [--limit 5]

For each `new` alert of the SOC API that the database lacks: store it with its logs, run the basic checks
(auto-close with a ticket, or keep), and for kept alerts build the prompt and run the LLM loop. Results go to the
`triage_*` tables; the analyst reviews them in the web UI (python -m src.webapp). One failing alert never stops
the queue. `--alert ID` re-runs the stages for an alert already stored.
"""

import argparse
import sys
from pathlib import Path

from .database.sync import AlertFeed
from .llm_triage.client import load_env
from .soc_api import SocApi
from .workflow import LLM_MODES, Outcome, Triage


def describe(outcome: Outcome) -> str:
    verdict = f" {outcome.verdict}/{outcome.severity}" if outcome.verdict else ""
    detail = f" - {outcome.detail[:160]}" if outcome.detail else ""
    return f"{outcome.alert_id}: {outcome.status}{verdict}{detail}"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tarvia L1 triage workflow")
    parser.add_argument("--llm", choices=LLM_MODES, default="none", help="LLM for kept alerts (default: none)")
    parser.add_argument("--model", help="model name (overrides TARVIA_LLM_MODEL or TARVIA_OPENAI_MODEL)")
    parser.add_argument("--limit", type=int, default=0, help="stop after N new alerts (0 = whole queue)")
    parser.add_argument("--db", type=Path, help="database (default: TARVIA_DB or data/tarvia.sqlite)")
    parser.add_argument("--alert", action="append", default=[], help="re-run the stages for a stored alert")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, api: SocApi | None = None) -> int:
    args = parse_args(argv)
    load_env()
    api = api or SocApi()
    failures = 0
    with Triage(args.db, api=api, llm_mode=args.llm, model=args.model) as triage:

        def run(alert_id: str) -> None:
            nonlocal failures
            try:
                print(describe(triage.process(alert_id)), flush=True)
            except Exception as exc:  # isolate failures: the next alert is still processed
                failures += 1
                print(f"{alert_id}: error - {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)

        if args.alert:
            for alert_id in args.alert:
                run(alert_id)
            return 1 if failures else 0
        done = 0
        with AlertFeed(args.db, api=api) as feed:
            while (args.limit <= 0 or done < args.limit) and (alert := feed.next_alert()) is not None:
                if feed.store(alert):
                    done += 1
                    run(alert["alert_id"])
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
