"""Embedding sarmalayicisi — varsayilan VoyageAI, takilabilir backend.

ML dedektorleri icin metni vektore cevirir. Varsayilan backend VoyageAI'dir
(anahtar .env'den, VOYAGE_API_KEY). `set_provider()` ile backend degistirilebilir;
boylece veri-egemenligi gereken (air-gapped / savunma) kurulumlar embedding'i
DIS CAGRI YAPMADAN yerel bir encoder ile uretebilir — embed() cagiran dedektorler
degismeden calismaya devam eder.
"""
from __future__ import annotations

import os
from typing import Callable, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

# Takilabilir embedding backend'i: (texts, input_type) -> vektor listesi.
# None ise varsayilan VoyageAI bulut backend'i kullanilir.
EmbedProvider = Callable[[List[str], str], List[List[float]]]
_provider: Optional[EmbedProvider] = None


def set_provider(provider: Optional[EmbedProvider]) -> None:
    """Embedding backend'ini degistir (None -> varsayilan VoyageAI'a don).

    provider: (texts: List[str], input_type: str) -> List[List[float]].
    Ornek (on-prem): yerel bir encoder'i baglayip embed()'i tamamen
    cevrimdisi/yerel calistirmak icin kullanilir."""
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
            raise RuntimeError("VOYAGE_API_KEY yok. .env'e ekle.")
        import voyageai
        _client = voyageai.Client(api_key=key)
    return _client


def embed(texts: List[str], input_type: str = "document") -> List[List[float]]:
    texts = list(texts)
    # Takili bir backend varsa (orn. on-prem yerel encoder) onu kullan — dis cagri yok.
    if _provider is not None:
        return _provider(texts, input_type)
    client = _get_client()
    out: List[List[float]] = []
    for i in range(0, len(texts), 128):
        batch = texts[i:i + 128]
        out.extend(client.embed(batch, model=MODEL, input_type=input_type).embeddings)
    return out
