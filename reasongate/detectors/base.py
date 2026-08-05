"""Detector interface. Every detector implements the same contract:
take text, return a Detection carrying its reason.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from reasongate.types import Detection


class Detector(ABC):
    name: str = "detector"
    stage: str = "input"   # "input" (the prompt) or "output" (the model's reply)

    @abstractmethod
    def scan(self, text: str) -> Detection:
        ...
