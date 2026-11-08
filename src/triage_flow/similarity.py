"""Alert embeddings in the database and retrieval of similar, already resolved alerts for the prompt.

Why: an N1 analyst checks how similar alerts were closed. Each alert's canonical text (embeddings.canonical, no
attacker free text beyond the rule description) is embedded once and stored in `alert_embeddings`. For a new alert
the k nearest neighbours that already have a verdict (operator-confirmed `alert_history` first, then valid tickets
other than needs_more_info) are offered to the LLM as a consistency reference, never as evidence.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from typing import Any

import numpy as np

from ..embeddings.canonical import canonical_alert_text
from ..embeddings.vulnerabilities import from_db as known_vulnerabilities

TOP_K = 3
MIN_SIMILARITY = 0.80
_cache: dict[tuple[int, str], tuple[int, list[str], np.ndarray]] = {}
_lock = threading.Lock()


def index_alerts(conn: sqlite3.Connection, alerts: dict[str, dict[str, Any]], encoder: Any, batch: int = 256) -> int:
    """Embed every alert whose canonical text has no vector for this encoder or has changed (for example a
    vulnerability on its host was opened or fixed). Returns how many were (re)embedded."""
    have = dict(conn.execute("SELECT alert_id, text_hash FROM alert_embeddings WHERE model = ?", (encoder.name,)))
    vulns = known_vulnerabilities(conn)
    texts = {a: canonical_alert_text(alerts[a], vulns) for a in alerts}
    hashes = {a: hashlib.sha1(t.encode("utf-8")).hexdigest() for a, t in texts.items()}
    pending = [a for a in sorted(alerts) if have.get(a) != hashes[a]]
    for start in range(0, len(pending), batch):
        ids = pending[start : start + batch]
        vectors = encoder.encode([texts[a] for a in ids]).astype(np.float32)
        conn.executemany(
            "INSERT OR REPLACE INTO alert_embeddings VALUES (?, ?, ?, ?, ?)",
            [(a, encoder.name, vectors.shape[1], v.tobytes(), hashes[a]) for a, v in zip(ids, vectors, strict=True)],
        )
    conn.commit()
    _cache.clear()
    return len(pending)


def _resolved(conn: sqlite3.Connection) -> dict[str, tuple[str, str, str]]:
    """alert_id -> (verdict, severity, origin) for alerts with a usable verdict."""
    out = {
        a: (v, s or "", "ticket")
        for a, v, s in conn.execute(
            "SELECT alert_id, verdict, severity FROM triage_tickets WHERE valid = 1 AND verdict <> 'needs_more_info'"
        )
    }
    for a, v in conn.execute("SELECT alert_id, verdict FROM alert_history"):
        out[a] = (v, out.get(a, ("", "", ""))[1], "operator")
    return out


def similar_resolved(
    conn: sqlite3.Connection, alert_id: str, k: int = TOP_K, min_similarity: float = MIN_SIMILARITY
) -> list[dict[str, Any]]:
    row = conn.execute("SELECT model, vector FROM alert_embeddings WHERE alert_id = ? LIMIT 1", (alert_id,)).fetchone()
    if row is None:
        return []
    model, blob = row
    query = np.frombuffer(blob, dtype=np.float32)
    resolved = _resolved(conn)
    resolved.pop(alert_id, None)
    if not resolved:
        return []
    key = (id(conn), model)
    with _lock:
        cached = _cache.get(key)
        signature = hash(frozenset(resolved))  # set identity, not size: a swap keeps the size but changes the ids
        if cached is None or cached[0] != signature:
            ids, vectors = [], []
            for a, v in conn.execute("SELECT alert_id, vector FROM alert_embeddings WHERE model = ?", (model,)):
                if a in resolved:
                    ids.append(a)
                    vectors.append(np.frombuffer(v, dtype=np.float32))
            matrix = np.vstack(vectors) if vectors else np.zeros((0, query.shape[0]), dtype=np.float32)
            cached = (signature, ids, matrix)
            _cache[key] = cached
    _, ids, matrix = cached
    if not ids:
        return []
    scores = matrix @ query
    order = np.argsort(-scores)
    rules = dict(conn.execute("SELECT alert_id, rule_id FROM alerts"))
    out = []
    for i in order:
        if ids[i] == alert_id or ids[i] not in resolved:
            continue
        if scores[i] < min_similarity or len(out) >= k:
            break
        verdict, severity, origin = resolved[ids[i]]
        out.append({"alert_id": ids[i], "rule_id": rules.get(ids[i], ""), "verdict": verdict,
                    "severity": severity or "?", "similarity": float(round(scores[i], 4)), "origin": origin})  # fmt: skip
    return out
