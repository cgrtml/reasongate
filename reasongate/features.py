"""Ozellik cikarimi: bir prompt'u yorumlanabilir sayisal vektore cevirir.

Ozellikler kasitli olarak AZ ve ANLAMLI tutulur ki agacin kararlari aciklanabilir
olsun (her ozellik bir cumleyle ifade edilebilir).
"""
from __future__ import annotations

from typing import List

import numpy as np

from reasongate.detectors.injection import InjectionDetector

FEATURE_NAMES: List[str] = [
    "kural_skoru",      # kural-tabanli injection skoru (0..1)
    "ml_benzerlik",     # bilinen saldirilara anlamsal benzerlik (0..1)
    "uzunluk",          # karakter sayisi (normalize)
    "kelime_sayisi",    # kelime sayisi (normalize)
    "ozel_karakter",    # alfanumerik olmayan oran
    "buyuk_harf",       # buyuk harf orani
    "rakam",            # rakam orani
]

_rule = InjectionDetector()


def _text_feats(p: str):
    p = p or ""
    n = max(len(p), 1)
    letters = [c for c in p if c.isalpha()]
    special = sum(1 for c in p if not c.isalnum() and not c.isspace())
    upper = sum(1 for c in letters if c.isupper())
    digits = sum(1 for c in p if c.isdigit())
    return [
        min(len(p) / 500.0, 1.0),
        min(len(p.split()) / 80.0, 1.0),
        special / n,
        (upper / len(letters)) if letters else 0.0,
        digits / n,
    ]


def build_features(prompts: List[str], ml_scores: List[float]) -> np.ndarray:
    """prompts + onceden hesaplanmis ml benzerlik skorlari -> (n, 7) matris."""
    rows = []
    for p, ml in zip(prompts, ml_scores):
        rule_score = _rule.scan(p).score
        rows.append([rule_score, float(ml)] + _text_feats(p))
    return np.asarray(rows, dtype=np.float32)
