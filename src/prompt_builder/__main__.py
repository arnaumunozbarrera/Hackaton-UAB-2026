"""Command-line entry point: print or save the prompt package for one or more alerts.

Why: lets the team inspect exactly what the LLM will receive before wiring the model call.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .builder import PromptBuilder, PromptConfig
from .context import DatasetContextSource
from .schema import SchemaMap


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m src.prompt_builder", description=__doc__)
    p.add_argument("alert_ids", nargs="+", help="alert ids, e.g. ALR-20261005-000172")
    p.add_argument("--data", default="docs", help="dataset directory (read-only)")
    p.add_argument("--format", choices=("text", "json", "messages"), default="text")
    p.add_argument("--schema-map", type=Path, help="JSON mapping logical -> physical table/column names")
    p.add_argument("--max-logs", type=int, default=40)
    p.add_argument("--window-hours", type=int, default=24)
    p.add_argument("--out", type=Path, help="write the output to this file instead of stdout")
    args = p.parse_args(argv)
    schema = SchemaMap.from_json(args.schema_map) if args.schema_map else SchemaMap()
    cfg = PromptConfig(
        data_dir=Path(args.data), max_logs=args.max_logs, window_hours=args.window_hours, schema_map=schema
    )
    builder = PromptBuilder(DatasetContextSource(args.data), cfg)
    packages = builder.build_many(args.alert_ids)
    if args.format == "text":
        text = "\n\n".join(f"=== SYSTEM ===\n{pk.system}\n=== USER ===\n{pk.user}" for pk in packages)
    else:
        items = [pk.to_dict() if args.format == "json" else pk.to_messages() for pk in packages]
        text = json.dumps(items if len(items) > 1 else items[0], ensure_ascii=False, indent=1, default=str)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
