"""Sizinti dedektoru (cikti tarafi, v0): model cevabinda sir/sistem-promptu/
PII benzeri icerik var mi? Kural tabanli, her bulguyu gerekceyle dondurur.
"""
from __future__ import annotations

import re
from typing import List, Tuple

from reasongate.detectors.base import Detector
from reasongate.types import Detection

_PATTERNS: List[Tuple[str, str, float]] = [
    (r"sk-[A-Za-z0-9]{16,}", "OpenAI tarzi API anahtari", 0.95),
    (r"(gho_|ghp_)[A-Za-z0-9]{20,}", "GitHub token", 0.95),
    (r"AKIA[0-9A-Z]{16}", "AWS access key", 0.95),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "ozel anahtar (PEM)", 0.97),
    (r"(my\s+system\s+prompt\s+is|sistem\s+promptum)", "sistem promptu sizdiriyor", 0.85),
    (r"you\s+are\s+a\s+helpful\s+assistant", "olasi sistem promptu metni", 0.5),
    (r"[\w.+-]+@[\w-]+\.[\w.-]+", "e-posta adresi (PII)", 0.4),
    (r"\b(?:\d[ -]?){13,16}\b", "olasi kart numarasi (PII)", 0.6),
]


class LeakageDetector(Detector):
    name = "leakage"
    stage = "output"

    def __init__(self, block_score: float = 0.8):
        self._compiled = [(re.compile(p, re.IGNORECASE), label, w) for p, label, w in _PATTERNS]
        self.block_score = block_score

    def scan(self, text: str) -> Detection:
        matches: List[str] = []
        max_w = 0.0
        for rx, label, w in self._compiled:
            if rx.search(text or ""):
                matches.append(label)
                max_w = max(max_w, w)
        triggered = max_w >= self.block_score
        reason = (f"{len(matches)} sizinti/PII kalibi eslesti." if matches
                  else "Sizinti/PII bulunmadi.")
        return Detection(self.name, triggered, round(max_w, 2), reason, matches)
