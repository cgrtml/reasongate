"""Policy: tespitlerden karar uretir (blokla / isaretle / izin ver) + gerekce.

Esik tabanli ve seffaf. Tek-dedektor esiklerine EK olarak, birden cok
ZAYIF sinyali noisy-OR ile birlestiren bir fuzyon katmani var: tek basina
hicbiri blok esigini gecmese de, birkac orta sinyal birikince blok uretir.
"""
from __future__ import annotations

from typing import List, Tuple

from reasongate.types import Detection

# Noisy-OR fuzyonunda gurultu tabani: bu degerin altindaki skorlar
# (mesru metinlerin rastgele dusuk sinyalleri) birlestirmeye katilmaz.
FUSION_FLOOR = 0.3


def fuse(scores: List[float], floor: float = FUSION_FLOOR) -> float:
    """Noisy-OR: birbirinden bagimsiz sinyalleri birlestirir.
    fused = 1 - PROD(1 - s_i). Sadece floor ustu sinyaller katilir ki
    mesru metnin rastgele dusuk skorlari yapay blok uretmesin."""
    contributing = [s for s in scores if s >= floor]
    prod = 1.0
    for s in contributing:
        prod *= (1.0 - s)
    return 1.0 - prod


def decide(detections: List[Detection],
           block_threshold: float = 0.8,
           flag_threshold: float = 0.5) -> Tuple[str, List[Detection]]:
    """Donus: (action, tetikleyen_tespitler). action in {allow, flag, block}.

    Blok karari uc yoldan biriyle verilir:
      1) Bir dedektorun KENDI kalibre esigi asilirsa (d.triggered), VEYA
      2) Tek bir skor block_threshold'u asarsa (Shield.block_threshold anlamli), VEYA
      3) Coklu zayif sinyalin NOISY-OR fuzyonu block_threshold'u asarsa.
    """
    if not detections:
        return "allow", []

    triggered = [d for d in detections if d.triggered]
    over_block = [d for d in detections if d.score >= block_threshold]
    blockers = triggered or over_block
    if blockers:
        return "block", blockers

    # Fuzyon: birden cok orta sinyal birikince blok.
    fused = fuse([d.score for d in detections])
    if fused >= block_threshold:
        contributors = [d for d in detections if d.score >= FUSION_FLOOR]
        return "block", contributors

    flagged = [d for d in detections if d.score >= flag_threshold]
    if flagged or fused >= flag_threshold:
        flagged = flagged or [d for d in detections if d.score >= FUSION_FLOOR]
        return "flag", flagged
    return "allow", []
