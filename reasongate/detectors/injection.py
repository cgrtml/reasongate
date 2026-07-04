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

# (regex, human-readable label, weight)  — labels are shown to users; patterns are not.
_PATTERNS: List[Tuple[str, str, float]] = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "ignore previous instructions", 0.9),
    (r"disregard\s+(the\s+)?(above|previous|system)", "disregard the above", 0.8),
    # TR patterns are diacritic-tolerant: match both "onceki tum" and "önceki tüm".
    (r"[öo]nceki\s+(t[üu]m\s+)?(talimatlar[ıi]|komutlar[ıi])\s+(yoksay|g[öo]zard[ıi]|unut)", "ignore previous instructions (TR)", 0.9),
    (r"(reveal|show|print|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions)", "reveal the system prompt", 0.9),
    # TR "reveal / leak the system prompt".
    (r"sistem\s+prompt\w*.{0,20}(g[öo]ster|if[şs]a|s[ıi]zd[ıi]r|yazd[ıi]r|payla[şs])", "reveal the system prompt (TR)", 0.9),
    (r"sistem\s+prompt", "reference to system prompt", 0.6),
    (r"\bDAN\b|do\s+anything\s+now", "DAN jailbreak", 0.85),
    (r"developer\s+mode", "developer mode jailbreak", 0.8),
    (r"you\s+are\s+now\s+", "role change (you are now)", 0.6),
    (r"act\s+as\s+(an?\s+)?(unrestricted|uncensored|evil)", "request unrestricted role", 0.85),
    (r"pretend\s+(to\s+be|you\s+are)", "role-play request", 0.5),
    (r"(base64|rot13|hex)\s*(decode|encode)", "encoding for evasion", 0.6),
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
            reason = f"{len(matches)} known injection/jailbreak pattern(s) matched."
        else:
            reason = "No known injection pattern found."
        return Detection(self.name, triggered, round(max_w, 2), reason, matches)
