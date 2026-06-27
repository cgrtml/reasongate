"""Prompt injection / jailbreak dedektoru (v0: kural/oruntu tabanli).

v0 bilincli olarak basit ve aciklanabilir: bilinen saldiri kaliplarini arar,
her eslesmeyi GEREKCE olarak dondurur. Sonraki surumde embedding-benzerligi +
soft decision tree ile ML'e cevrilecek (ayni arayuz korunur).
"""
from __future__ import annotations

import re
from typing import List, Tuple

from reasongate.detectors.base import Detector
from reasongate.types import Detection

# (regex, insan-okunur etiket, agirlik)
_PATTERNS: List[Tuple[str, str, float]] = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "onceki talimatlari yoksay", 0.9),
    (r"disregard\s+(the\s+)?(above|previous|system)", "yukaridakini gozardi et", 0.8),
    # TR kaliplari diyakritik-toleransli: hem "onceki tum" hem "önceki tüm" eslesir.
    (r"[öo]nceki\s+(t[üu]m\s+)?(talimatlar[ıi]|komutlar[ıi])\s+(yoksay|g[öo]zard[ıi]|unut)", "onceki talimatlari yoksay (TR)", 0.9),
    (r"(reveal|show|print|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions)", "sistem promptunu sizdir", 0.9),
    # TR "sistem promptunu göster/ifşa et/sızdır/yazdır" — guclu sizdirma niyeti.
    (r"sistem\s+prompt\w*.{0,20}(g[öo]ster|if[şs]a|s[ıi]zd[ıi]r|yazd[ıi]r|payla[şs])", "sistem promptunu sizdir (TR)", 0.9),
    (r"sistem\s+prompt", "sistem promptuna atif", 0.6),
    (r"\bDAN\b|do\s+anything\s+now", "DAN jailbreak", 0.85),
    (r"developer\s+mode", "developer mode jailbreak", 0.8),
    (r"you\s+are\s+now\s+", "rol degistirme (you are now)", 0.6),
    (r"act\s+as\s+(an?\s+)?(unrestricted|uncensored|evil)", "kisitlamasiz rol iste", 0.85),
    (r"pretend\s+(to\s+be|you\s+are)", "rol yapma talebi", 0.5),
    (r"(base64|rot13|hex)\s*(decode|encode)", "kacis icin kodlama", 0.6),
]


class InjectionDetector(Detector):
    name = "injection"
    stage = "input"

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
        if matches:
            reason = f"{len(matches)} bilinen injection/jailbreak kalibi eslesti."
        else:
            reason = "Bilinen injection kalibi bulunmadi."
        return Detection(self.name, triggered, round(max_w, 2), reason, matches)
