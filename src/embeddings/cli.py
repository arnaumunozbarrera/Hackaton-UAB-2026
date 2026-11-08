"""CLI for inspecting and generating local alert embeddings."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .canonical import canonical_alert_text, load_alerts
from .log_context import (
    collect_dataset_candidates,
    collect_dataset_candidates_for_alerts,
    log_context_text,
    select_log_context,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m src.embeddings.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("render", "show canonical alert text"),
        ("context", "select diverse log context for one alert"),
        ("embed", "generate local embeddings"),
        ("plot", "create an interactive 2D vector-space plot"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument(
            "--input",
            default="tmp/alert_embeddings.npz"
            if name == "plot"
            else "docs/03_alertas/alertas_muestra_desarrollo.jsonl",
        )
        command.add_argument("--limit", type=int, default=0, help="0 means all alerts")
        if name == "context":
            command.add_argument("--data", default="docs")
            command.add_argument("--alert-id", default="ALR-20261005-000301")
            command.add_argument("--budget", type=int, default=20)
            command.add_argument("--per-source", type=int, default=5)
        if name == "embed":
            command.add_argument("--output", default="tmp/alert_embeddings.npz")
            command.add_argument("--model", default=os.getenv("TARVIA_EMBEDDING_MODEL", "BAAI/bge-m3"))
            command.add_argument("--device", default=os.getenv("TARVIA_EMBEDDING_DEVICE", "cpu"))
            command.add_argument("--batch-size", type=int, default=int(os.getenv("TARVIA_EMBEDDING_BATCH_SIZE", "16")))
            command.add_argument("--with-context", action="store_true", help="also embed selected log context")
            command.add_argument("--data", default="docs")
            command.add_argument("--budget", type=int, default=20)
            command.add_argument("--per-source", type=int, default=5)
        if name == "plot":
            command.add_argument("--alerts", default="docs/03_alertas/alertas.jsonl")
            command.add_argument("--output", default="tmp/alert_vector_space.html")
            command.add_argument("--space", choices=("alert", "context"), default="alert")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "plot":
        from .visualize import create_html

        result = create_html(args.input, args.alerts, args.output, args.space)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    alerts = list(load_alerts(args.input))
    if args.limit:
        alerts = alerts[: args.limit]

    if args.command == "render":
        for alert in alerts:
            print(f"[{alert['alert_id']}]\n{canonical_alert_text(alert)}\n")
        return 0

    if args.command == "context":
        from ..log_noise_discard.loaders import load_alerts as load_dataset_alerts

        alerts = load_dataset_alerts(Path(args.data))
        if args.alert_id not in alerts:
            raise SystemExit(f"alerta no encontrada: {args.alert_id}")
        candidates = collect_dataset_candidates(
            args.data, alerts[args.alert_id], max_candidates=max(args.budget * 5, 100)
        )
        selected = select_log_context(alerts[args.alert_id], candidates, args.budget, args.per_source)
        print(
            json.dumps(
                {
                    "alert_id": args.alert_id,
                    "budget": args.budget,
                    "selected": len(selected),
                    "by_source": {
                        source: sum(item.source == source for item in selected)
                        for source in sorted({item.source for item in selected})
                    },
                    "logs": [
                        {
                            "event_id": item.event_id,
                            "source": item.source,
                            "score": round(item.score, 3),
                            "reason": item.reason,
                        }
                        for item in selected
                    ],
                    "context_text": log_context_text(selected),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(args.model, device=args.device)
    texts = [canonical_alert_text(alert) for alert in alerts]
    alert_vectors = model.encode(texts, batch_size=args.batch_size, normalize_embeddings=True, show_progress_bar=True)
    context_vectors = None
    context_counts: list[int] = []
    if args.with_context:
        alert_map = {alert["alert_id"]: alert for alert in alerts}
        candidates = collect_dataset_candidates_for_alerts(
            args.data, alert_map, max_candidates=max(args.budget * 5, 100)
        )
        contexts = [
            select_log_context(alert, candidates[alert["alert_id"]], args.budget, args.per_source) for alert in alerts
        ]
        context_texts = [log_context_text(rows) for rows in contexts]
        context_counts = [len(rows) for rows in contexts]
        non_empty = [text for text in context_texts if text]
        if non_empty:
            non_empty_vectors = model.encode(
                non_empty, batch_size=args.batch_size, normalize_embeddings=True, show_progress_bar=True
            )
            import numpy as np

            context_vectors = np.zeros_like(alert_vectors)
            position = 0
            for index, text in enumerate(context_texts):
                if text:
                    context_vectors[index] = non_empty_vectors[position]
                    position += 1

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    import numpy as np

    arrays = {
        "alert_ids": np.array([a["alert_id"] for a in alerts]),
        "embeddings": alert_vectors,
        "alert_embeddings": alert_vectors,
    }
    if context_vectors is not None:
        arrays["context_embeddings"] = context_vectors
        arrays["context_counts"] = np.array(context_counts, dtype=np.int32)
    np.savez_compressed(output, **arrays)
    manifest = output.with_suffix(".json")
    manifest.write_text(
        json.dumps(
            {
                "model": args.model,
                "device": args.device,
                "count": len(alerts),
                "dimensions": int(alert_vectors.shape[1]),
                "with_context": bool(args.with_context),
                "context_budget": args.budget if args.with_context else None,
                "context_per_source": args.per_source if args.with_context else None,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    suffix = " + context embeddings" if args.with_context else ""
    print(f"Generated {len(alerts)} alert embeddings ({alert_vectors.shape[1]} dimensions){suffix} -> {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
