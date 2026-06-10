"""Cekirdek veri tipleri.

Her tespit (Detection) bir GEREKCE tasir — kalkanin "kara kutu degil,
aciklanabilir" olmasinin temeli budur.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Detection:
    detector: str            # dedektor adi (orn. "injection")
    triggered: bool          # esik asildi mi
    score: float             # 0..1 risk skoru
    reason: str              # insan-okunur gerekce ("neden")
    matches: List[str] = field(default_factory=list)  # tetikleyen kanitlar


@dataclass
class ShieldResult:
    action: str              # "allow" | "flag" | "block"
    stage: str               # "input" | "output"
    detections: List[Detection]
    output: Optional[str] = None   # blok degilse modelin (taranmis) ciktisi

    @property
    def allowed(self) -> bool:
        return self.action != "block"

    def explain(self) -> str:
        """Insan-okunur ozet: ne yapildi ve NEDEN."""
        head = {"allow": "IZIN VERILDI", "flag": "ISARETLENDI", "block": "BLOKLANDI"}[self.action]
        lines = [f"[{self.stage}] {head}"]
        for d in self.detections:
            mark = "✗" if d.triggered else "·"
            lines.append(f"  {mark} {d.detector} (skor={d.score:.2f}): {d.reason}")
            if d.triggered and d.matches:
                lines.append(f"      kanit: {', '.join(d.matches[:5])}")
        return "\n".join(lines)
