"""Command-line entry point: print the noise table and optionally export the informative logs.

Why: lets the team inspect the reduction and feed the selected logs to later steps without writing code.
Outputs are written only outside the dataset directory.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .config import ALL_STAGES, NoiseFilterConfig
from .pipeline import FilterResult, run_filter


def _parse(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m src.log_noise_discard", description=__doc__)
    p.add_argument("--data", default="docs", help="dataset directory (read-only), default: docs")
    p.add_argument("--stages", default=",".join(ALL_STAGES), help="stages to apply, e.g. N1,N2 (N0 always applies)")
    p.add_argument("--tau", type=float, default=0.8, help="N3 share of a rule's alerts (default 0.8)")
    p.add_argument("--out", type=Path, help="JSONL with the informative logs")
    p.add_argument("--groups-out", type=Path, help="JSON with the N3 groups")
    p.add_argument("--stats-out", type=Path, help="JSON with the stage table")
    return p.parse_args(argv)


def _guard_output(path: Path, data_dir: Path) -> None:
    if path.resolve().is_relative_to(data_dir.resolve()):
        raise SystemExit(f"refusing to write inside the read-only dataset: {path}")


def _print_table(result: FilterResult) -> None:
    print(f"{'stage':<6}{'discarded':>11}{'remaining':>11}{'remaining MB':>14}  description")
    for s in result.stats:
        print(
            f"{s.stage:<6}{s.discarded_events:>11,}{s.remaining_events:>11,}{s.remaining_bytes / 1e6:>14.2f}  {s.description}"
        )


def _export(result: FilterResult, args: argparse.Namespace) -> None:
    if args.out:
        alerts_by_event: dict[str, list[str]] = {}
        for aid, eids in result.alert_events.items():
            for eid in eids:
                alerts_by_event.setdefault(eid, []).append(aid)
        with args.out.open("w", encoding="utf-8") as fh:
            for rec in result.iter_kept():
                row = {
                    "event_id": rec.event_id,
                    "source": rec.source,
                    "alert_ids": alerts_by_event.get(rec.event_id, []),
                    "event": rec.event,
                }
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    if args.groups_out:
        args.groups_out.write_text(
            json.dumps([asdict(g) for g in result.groups], ensure_ascii=False, indent=1), "utf-8"
        )
    if args.stats_out:
        args.stats_out.write_text(json.dumps([asdict(s) for s in result.stats], indent=1), "utf-8")


def main(argv: list[str] | None = None) -> int:
    args = _parse(argv)
    data_dir = Path(args.data)
    for path in (args.out, args.groups_out, args.stats_out):
        if path:
            _guard_output(path, data_dir)
    stages = tuple(s.strip().upper() for s in args.stages.split(",") if s.strip())
    unknown = set(stages) - set(ALL_STAGES)
    if unknown:
        raise SystemExit(f"unknown stages: {sorted(unknown)}")
    result = run_filter(data_dir, NoiseFilterConfig(stages=stages, tau=args.tau))
    _print_table(result)
    _export(result, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
