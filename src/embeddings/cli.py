"""CLI for inspecting and generating local alert embeddings."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .canonical import canonical_alert_text, load_alerts


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m src.embeddings.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (("render", "show canonical alert text"), ("embed", "generate local embeddings")):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("--input", default="docs/03_alertas/alertas_muestra_desarrollo.jsonl")
        command.add_argument("--limit", type=int, default=0, help="0 means all alerts")
        if name == "embed":
            command.add_argument("--output", default="tmp/alert_embeddings.npz")
            command.add_argument("--model", default=os.getenv("TARVIA_EMBEDDING_MODEL", "BAAI/bge-m3"))
            command.add_argument("--device", default=os.getenv("TARVIA_EMBEDDING_DEVICE", "cpu"))
            command.add_argument("--batch-size", type=int, default=int(os.getenv("TARVIA_EMBEDDING_BATCH_SIZE", "16")))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    alerts = list(load_alerts(args.input))
    if args.limit:
        alerts = alerts[: args.limit]

    if args.command == "render":
        for alert in alerts:
            print(f"[{alert['alert_id']}]\n{canonical_alert_text(alert)}\n")
        return 0

    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(args.model, device=args.device)
    texts = [canonical_alert_text(alert) for alert in alerts]
    vectors = model.encode(texts, batch_size=args.batch_size, normalize_embeddings=True, show_progress_bar=True)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    import numpy as np

    np.savez_compressed(output, alert_ids=np.array([a["alert_id"] for a in alerts]), embeddings=vectors)
    manifest = output.with_suffix(".json")
    manifest.write_text(
        json.dumps(
            {"model": args.model, "device": args.device, "count": len(alerts), "dimensions": int(vectors.shape[1])},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Generated {len(alerts)} embeddings ({vectors.shape[1]} dimensions) -> {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
