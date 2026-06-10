"""Coklu-tur (multi-turn) kalkani: kademeli / crescendo jailbreak savunmasi.

Modern jailbreak'lerin cogu TEK promptta degil, birden cok turda kademeli
ilerler: her tur masum gorunur, ama biriken niyet sinirlari asar. Tek-prompt
tarama bunu kacirir.

ConversationShield, oturum boyunca her kullanici turunun risk skorunu
zaman-azaltimli (decay) noisy-OR ile biriktirir. Tekil tur bloklanmasa bile,
BIRIKEN risk block_threshold'u asarsa oturum bloklanir — gerekceyle.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from reasongate import policy
from reasongate.shield import Shield
from reasongate.types import Detection, ShieldResult


@dataclass
class TurnResult:
    action: str                       # bu turun karari: allow | flag | block
    turn_risk: float                  # bu turun tekil risk skoru
    cumulative_risk: float            # biriken (decay'li noisy-OR) risk
    result: ShieldResult              # altta yatan tekil-tur sonucu
    output: Optional[str] = None      # (llm_fn verildiyse) taranmis cikti

    def explain(self) -> str:
        head = {"allow": "IZIN", "flag": "ISARET", "block": "BLOK"}[self.action]
        return (f"[tur] {head}  tekil={self.turn_risk:.2f}  biriken={self.cumulative_risk:.2f}\n"
                + self.result.explain())


class ConversationShield:
    def __init__(self,
                 shield: Optional[Shield] = None,
                 decay: float = 0.7,
                 block_threshold: float = 0.8,
                 flag_threshold: float = 0.5):
        self.shield = shield or Shield()
        self.decay = decay                     # eski turlarin agirlik azaltimi
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self._turn_scores: List[float] = []    # her kullanici turunun tekil riski

    def reset(self) -> None:
        self._turn_scores = []

    def _cumulative(self) -> float:
        """Zaman-azaltimli noisy-OR: yeni turlar agirlikli, eskiler soner.
        En son tur tam agirlik; bir onceki *decay; iki onceki *decay^2 ..."""
        prod = 1.0
        for age, s in enumerate(reversed(self._turn_scores)):
            weighted = s * (self.decay ** age)
            prod *= (1.0 - weighted)
        return 1.0 - prod

    def turn(self, prompt: str,
             llm_fn: Optional[Callable[[str], str]] = None,
             context=None) -> TurnResult:
        """Bir kullanici turunu isler. llm_fn verilirse korumali cagrilir."""
        single = self.shield.scan_input(prompt)
        turn_risk = max([d.score for d in single.detections], default=0.0)
        self._turn_scores.append(turn_risk)

        cumulative = self._cumulative()

        # Karar: tekil-tur karari VEYA biriken risk.
        action = single.action
        detections = list(single.detections)
        if cumulative >= self.block_threshold and action != "block":
            action = "block"
            detections.append(Detection(
                "multi_turn", True, round(cumulative, 2),
                f"Kademeli/crescendo saldiri: {len(self._turn_scores)} turda biriken "
                f"risk {cumulative:.2f} >= {self.block_threshold}.", []))
        elif cumulative >= self.flag_threshold and action == "allow":
            action = "flag"
            detections.append(Detection(
                "multi_turn", False, round(cumulative, 2),
                f"Biriken risk yukseliyor ({cumulative:.2f}); kademeli saldiri olabilir.", []))

        result = ShieldResult(action=action, stage="input", detections=detections)
        if action == "block" or llm_fn is None:
            return TurnResult(action, turn_risk, cumulative, result)

        # izin/flag -> LLM cagir, ciktiyi tara
        out = self.shield.protect(prompt, llm_fn, context=context)
        final_action = "block" if out.action == "block" else action
        return TurnResult(final_action, turn_risk, cumulative, out, output=out.output)
