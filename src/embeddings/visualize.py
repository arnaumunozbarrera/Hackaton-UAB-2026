"""Create an interactive 2D approximation of the alert vector space."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np


def project(vectors: np.ndarray, random_state: int = 42) -> tuple[np.ndarray, str]:
    """Project vectors with UMAP, falling back to PCA when optional UMAP is unavailable."""
    if len(vectors) < 3:
        raise ValueError("se necesitan al menos 3 vectores para proyectar")
    try:
        import umap

        reducer = umap.UMAP(
            n_components=2,
            metric="cosine",
            n_neighbors=min(15, len(vectors) - 1),
            min_dist=0.1,
            random_state=random_state,
        )
        return reducer.fit_transform(vectors), "UMAP cosine"
    except (ImportError, RuntimeError):
        from sklearn.decomposition import PCA

        return PCA(n_components=2, random_state=random_state).fit_transform(vectors), "PCA fallback"


def create_html(
    embedding_file: str | Path,
    alerts_file: str | Path,
    output_file: str | Path,
    space: str = "alert",
) -> dict[str, Any]:
    """Create an HTML scatter plot and return its metadata."""
    import plotly.graph_objects as go

    embeddings = np.load(embedding_file, allow_pickle=False)
    key = "context_embeddings" if space == "context" else "alert_embeddings"
    if key not in embeddings:
        raise ValueError(f"el archivo no contiene {key}")
    vectors = embeddings[key]
    rows = []
    with Path(alerts_file).open(encoding="utf-8") as fh:
        by_id = {}
        for line in fh:
            if line.strip():
                alert = json.loads(line)
                by_id[alert["alert_id"]] = alert
    alert_ids = embeddings["alert_ids"].tolist()
    valid = np.ones(len(alert_ids), dtype=bool)
    if space == "context" and "context_counts" in embeddings:
        valid = embeddings["context_counts"] > 0
    for alert_id, vector, is_valid in zip(alert_ids, vectors, valid, strict=True):
        if not is_valid:
            continue
        alert = by_id[str(alert_id)]
        mitre = alert.get("mitre") or {}
        rows.append(
            {
                "alert_id": str(alert_id),
                "x_vector": vector,
                "source": alert.get("source_product", "unknown"),
                "severity": alert.get("severity", "unknown"),
                "rule_id": alert.get("rule_id", ""),
                "rule_name": alert.get("rule_name", ""),
                "technique": mitre.get("technique_id", ""),
                "related_logs": int(alert.get("related_event_count", len(alert.get("related_events") or []))),
            }
        )
    projected, method = project(np.asarray([row["x_vector"] for row in rows]))
    for row, point in zip(rows, projected, strict=True):
        row["x"], row["y"] = float(point[0]), float(point[1])
    symbols = {"low": "circle", "medium": "diamond", "high": "triangle-up", "critical": "star", "unknown": "x"}
    figure = go.Figure()
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault((row["source"], row["severity"]), []).append(row)
    for (source, severity), group in sorted(groups.items()):
        figure.add_trace(
            go.Scatter(
                x=[row["x"] for row in group],
                y=[row["y"] for row in group],
                mode="markers",
                name=f"{source} · {severity}",
                marker={"size": 9, "opacity": 0.78, "symbol": symbols.get(severity, "circle")},
                customdata=[
                    [row["alert_id"], row["rule_id"], row["rule_name"], row["technique"], row["related_logs"]]
                    for row in group
                ],
                hovertemplate=(
                    "<b>%{customdata[0]}</b><br>Regla: %{customdata[1]}<br>%{customdata[2]}"
                    "<br>MITRE: %{customdata[3]}<br>Logs relacionados: %{customdata[4]}<extra></extra>"
                ),
            )
        )
    figure.update_layout(
        template="plotly_white",
        title=f"Tarvia SOC · espacio vectorial de alertas ({method})",
        xaxis_title="proyección 1",
        yaxis_title="proyección 2",
        legend_title_text="Fuente · severidad",
    )
    output = Path(output_file)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.write_html(output, include_plotlyjs="cdn")
    return {"output": str(output), "count": len(rows), "method": method, "space": space}
