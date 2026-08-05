"""System-prompt leak detection with a canary token.

A hidden 'canary' token is planted in the system prompt. If the model repeats
that token in its OUTPUT, a system-prompt leak is PROVEN rather than guessed —
no regex heuristic required. This is the deterministic counterpart of the
"possible system-prompt text" hint (0.5) in leakage.py.

Usage:
    canary = generate_canary()
    system_prompt = f"... [trace:{canary}] ..."   # given to the model, not the user
    shield = Shield(output_detectors=[CanaryLeakDetector(canary), LeakageDetector()])
"""
from __future__ import annotations

import secrets

from reasongate.detectors.base import Detector
from reasongate.types import Detection


def generate_canary(prefix: str = "LS") -> str:
    """Generate an unpredictable, unique canary token."""
    return f"{prefix}-{secrets.token_hex(8)}"


class CanaryLeakDetector(Detector):
    name = "canary_leak"
    stage = "output"

    def __init__(self, canary: str):
        if not canary:
            raise ValueError("CanaryLeakDetector requires a non-empty canary")
        self.canary = canary

    def scan(self, text: str) -> Detection:
        hit = self.canary in (text or "")
        score = 0.99 if hit else 0.0
        reason = ("System prompt DEFINITELY leaked: the hidden canary token "
                  "appeared in the output." if hit else
                  "No canary token in the output (system prompt not leaked).")
        matches = [self.canary] if hit else []
        return Detection(self.name, hit, score, reason, matches)
