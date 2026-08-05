"""Embedding wrapper — VoyageAI by default, with a pluggable backend.

Turns text into vectors for the ML detectors. The default backend is VoyageAI
(key from the environment or .env, VOYAGE_API_KEY). `set_provider()` swaps the
backend, so deployments that require data sovereignty (air-gapped / defense)
can produce embeddings with a LOCAL encoder and NO outbound call — the
detectors calling embed() keep working unchanged.
"""
from __future__ import annotations

import os
from typing import Callable, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

# Pluggable embedding backend: (texts, input_type) -> list of vectors.
# When None, the default VoyageAI cloud backend is used.
EmbedProvider = Callable[[List[str], str], List[List[float]]]
_provider: Optional[EmbedProvider] = None


def set_provider(provider: Optional[EmbedProvider]) -> None:
    """Swap the embedding backend (None -> back to the VoyageAI default).

    provider: (texts: List[str], input_type: str) -> List[List[float]].
    Example (on-prem): plug in a local encoder to run embed() fully offline."""
    global _provider
    _provider = provider


def get_provider() -> Optional[EmbedProvider]:
    return _provider


def _load_dotenv():
    path = os.path.join(_ROOT, ".env")
    if not os.path.exists(path):
        return
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()
MODEL = os.environ.get("VOYAGE_MODEL", "voyage-3")
_client = None


def _get_client():
    global _client
    if _client is None:
        key = os.environ.get("VOYAGE_API_KEY")
        if not key:
            raise RuntimeError(
                "VOYAGE_API_KEY is not set. Add it to your environment or .env, "
                "or plug in a local backend with embeddings.set_provider().")
        import voyageai
        _client = voyageai.Client(api_key=key)
    return _client


def embed(texts: List[str], input_type: str = "document") -> List[List[float]]:
    texts = list(texts)
    # If a backend is plugged in (e.g. an on-prem local encoder), use it — no outbound call.
    if _provider is not None:
        return _provider(texts, input_type)
    client = _get_client()
    out: List[List[float]] = []
    for i in range(0, len(texts), 128):
        batch = texts[i:i + 128]
        out.extend(client.embed(batch, model=MODEL, input_type=input_type).embeddings)
    return out
