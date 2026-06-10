"""Canary-token ile sistem-promptu sizinti tespiti.

Sistem promptuna gizli bir 'canary' (tuzak) belirteci gomulur. Model
bu belirteci CIKTISINDA tekrarlarsa, sistem promptunu sizdirdigi KESIN
olarak kanitlanmis olur — regex tahminine gerek kalmaz. Bu, leakage.py'deki
"olasi sistem promptu metni" (0.5) sezgisinin kesin/deterministik versiyonu.

Kullanim:
    canary = generate_canary()
    system_prompt = f"... [trace:{canary}] ..."   # modele verilir, kullaniciya degil
    shield = Shield(output_detectors=[CanaryLeakDetector(canary), LeakageDetector()])
"""
from __future__ import annotations

import secrets

from reasongate.detectors.base import Detector
from reasongate.types import Detection


def generate_canary(prefix: str = "LS") -> str:
    """Tahmin edilemez, benzersiz bir canary belirteci uretir."""
    return f"{prefix}-{secrets.token_hex(8)}"


class CanaryLeakDetector(Detector):
    name = "canary_leak"
    stage = "output"

    def __init__(self, canary: str):
        if not canary:
            raise ValueError("CanaryLeakDetector bos olmayan bir canary ister")
        self.canary = canary

    def scan(self, text: str) -> Detection:
        hit = self.canary in (text or "")
        score = 0.99 if hit else 0.0
        reason = ("Sistem promptu KESIN sizdirildi: gizli canary belirteci "
                  "ciktida gorundu." if hit else
                  "Canary belirteci ciktida yok (sistem promptu sizmadi).")
        matches = [self.canary] if hit else []
        return Detection(self.name, hit, score, reason, matches)
