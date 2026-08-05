"""Multi-turn shield: defense against gradual / crescendo jailbreaks.

Most modern jailbreaks do not arrive in a SINGLE prompt; they escalate across
several turns. Each turn looks innocent on its own, but the accumulated intent
crosses the line. Single-prompt scanning misses this.

ConversationShield accumulates the risk score of every user turn over the
session with a time-decayed noisy-OR. Even when no individual turn is blocked,
the ACCUMULATED risk crossing block_threshold blocks the session — with a reason.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from reasongate import policy
from reasongate.shield import Shield
from reasongate.types import Detection, ShieldResult


@dataclass
class TurnResult:
    action: str                       # this turn's decision: allow | flag | block
    turn_risk: float                  # this turn's own risk score
    cumulative_risk: float            # accumulated (decayed noisy-OR) risk
    result: ShieldResult              # the underlying single-turn result
    output: Optional[str] = None      # scanned output (when llm_fn was given)

    def explain(self) -> str:
        head = {"allow": "ALLOWED", "flag": "FLAGGED", "block": "BLOCKED"}[self.action]
        return (f"[turn] {head}  this-turn={self.turn_risk:.2f}  "
                f"cumulative={self.cumulative_risk:.2f}\n"
                + self.result.explain())


class ConversationShield:
    def __init__(self,
                 shield: Optional[Shield] = None,
                 decay: float = 0.7,
                 block_threshold: float = 0.8,
                 flag_threshold: float = 0.5):
        self.shield = shield or Shield()
        self.decay = decay                     # how fast older turns lose weight
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self._turn_scores: List[float] = []    # each user turn's own risk

    def reset(self) -> None:
        self._turn_scores = []

    def _cumulative(self) -> float:
        """Time-decayed noisy-OR: recent turns weigh more, older ones fade.
        The latest turn carries full weight; the one before it *decay; the one
        before that *decay^2, and so on."""
        prod = 1.0
        for age, s in enumerate(reversed(self._turn_scores)):
            weighted = s * (self.decay ** age)
            prod *= (1.0 - weighted)
        return 1.0 - prod

    def turn(self, prompt: str,
             llm_fn: Optional[Callable[[str], str]] = None,
             context=None) -> TurnResult:
        """Process one user turn. If llm_fn is given, it is called guarded."""
        single = self.shield.scan_input(prompt)
        turn_risk = max([d.score for d in single.detections], default=0.0)
        self._turn_scores.append(turn_risk)

        cumulative = self._cumulative()

        # Decision: the single-turn verdict OR the accumulated risk.
        action = single.action
        detections = list(single.detections)
        if cumulative >= self.block_threshold and action != "block":
            action = "block"
            detections.append(Detection(
                "multi_turn", True, round(cumulative, 2),
                f"Gradual/crescendo attack: risk accumulated over "
                f"{len(self._turn_scores)} turns is {cumulative:.2f} >= "
                f"{self.block_threshold}.", []))
        elif cumulative >= self.flag_threshold and action == "allow":
            action = "flag"
            detections.append(Detection(
                "multi_turn", False, round(cumulative, 2),
                f"Accumulated risk is rising ({cumulative:.2f}); this may be a "
                f"gradual attack.", []))

        result = ShieldResult(action=action, stage="input", detections=detections)
        if action == "block" or llm_fn is None:
            return TurnResult(action, turn_risk, cumulative, result)

        # allow/flag -> call the LLM and scan its output
        out = self.shield.protect(prompt, llm_fn, context=context)
        final_action = "block" if out.action == "block" else action
        return TurnResult(final_action, turn_risk, cumulative, out, output=out.output)
