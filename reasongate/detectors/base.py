"""Dedektor arayuzu. Tum dedektorler ayni sozlesmeyi uygular:
metni alir, gerekceli bir Detection dondurur.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from reasongate.types import Detection


class Detector(ABC):
    name: str = "detector"
    stage: str = "input"   # "input" (prompt) veya "output" (model cevabi)

    @abstractmethod
    def scan(self, text: str) -> Detection:
        ...
