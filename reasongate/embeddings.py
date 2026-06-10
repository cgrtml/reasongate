"""VoyageAI embedding sarmalayicisi (+ hafif .env yukleyici).

ML dedektorleri icin metni vektore cevirir. Anahtar .env'den (VOYAGE_API_KEY).
"""
from __future__ import annotations

import os
from typing import List

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


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
            raise RuntimeError("VOYAGE_API_KEY yok. .env'e ekle.")
        import voyageai
        _client = voyageai.Client(api_key=key)
    return _client


def embed(texts: List[str], input_type: str = "document") -> List[List[float]]:
    client = _get_client()
    out: List[List[float]] = []
    for i in range(0, len(texts), 128):
        batch = texts[i:i + 128]
        out.extend(client.embed(batch, model=MODEL, input_type=input_type).embeddings)
    return out
