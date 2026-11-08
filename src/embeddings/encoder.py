"""Text encoders for alert embeddings.

Why: the agreed model is BAAI/bge-m3 (sentence-transformers, ~2 GB). It is used whenever it is installed; otherwise
(CI, small machines, offline demo) a deterministic hashing encoder over words and character trigrams keeps the
pipeline working with the same interface. Vectors are L2-normalised, so cosine similarity is a dot product. The
encoder name is stored next to each vector, so vectors from different encoders are never compared.

TARVIA_EMBEDDING_BACKEND = auto (default) | sentence-transformers | hashing
"""

from __future__ import annotations

import hashlib
import os
import re

import numpy as np

_TOKEN = re.compile(r"[\w.@:/-]+", re.UNICODE)


class HashingEncoder:
    """Signed feature hashing of words and character trigrams (no model download, fully deterministic)."""

    def __init__(self, dim: int = 512) -> None:
        self.dim = dim
        self.name = f"hashing-ngram-{dim}"

    def _features(self, text: str) -> list[str]:
        words = _TOKEN.findall(text.lower())
        grams = [w[i : i + 3] for w in words for i in range(max(1, len(w) - 2))]
        return [f"w:{w}" for w in words] + [f"g:{g}" for g in grams]

    def encode(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for row, text in enumerate(texts):
            for feature in self._features(text):
                digest = hashlib.md5(feature.encode("utf-8")).digest()
                index = int.from_bytes(digest[:4], "little") % self.dim
                out[row, index] += 1.0 if digest[4] & 1 else -1.0
            norm = np.linalg.norm(out[row])
            if norm:
                out[row] /= norm
        return out


class SentenceTransformerEncoder:
    def __init__(self, model: str | None = None, device: str | None = None, batch_size: int | None = None) -> None:
        from sentence_transformers import SentenceTransformer

        self.model_name = model or os.environ.get("TARVIA_EMBEDDING_MODEL", "BAAI/bge-m3")
        self.batch_size = batch_size or int(os.environ.get("TARVIA_EMBEDDING_BATCH_SIZE", "16"))
        self.model = SentenceTransformer(
            self.model_name, device=device or os.environ.get("TARVIA_EMBEDDING_DEVICE", "cpu")
        )
        self.name = self.model_name

    def encode(self, texts: list[str]) -> np.ndarray:
        vectors = self.model.encode(
            texts, batch_size=self.batch_size, normalize_embeddings=True, show_progress_bar=False
        )
        return np.asarray(vectors, dtype=np.float32)


def get_encoder(backend: str | None = None):  # noqa: ANN201 - one of the two encoders
    choice = (backend or os.environ.get("TARVIA_EMBEDDING_BACKEND", "auto")).lower()
    if choice in ("auto", "sentence-transformers"):
        try:
            return SentenceTransformerEncoder()
        except ImportError:
            if choice == "sentence-transformers":
                raise
    return HashingEncoder()
