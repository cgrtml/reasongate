"""Prompt-injection / jailbreak detector (rule / pattern based).

Deliberately simple and explainable: it looks for known attack phrasings and
returns every match as the REASON for the decision. Semantic recall for novel,
never-seen phrasings is explicitly NOT this layer's job — that belongs to the
embedding-based detector shipped in the separate enterprise add-on (see the
"What this is not" section of the README).

Scope discipline for anyone editing this file: a pattern must cover a known
attack FAMILY and its synonyms, never a guess at intent. Widening a family is
legitimate; inventing a semantic rule is not. Every change is measured against
NotInject (`python eval/public_bench.py`, 339 benign trigger-word-laden
prompts) so that broader coverage never costs over-defense.
"""
from __future__ import annotations

import re
from typing import List, Tuple

from reasongate.detectors.base import Detector
from reasongate.types import Detection

# --- Reusable fragments -----------------------------------------------------
# The two biggest families (instruction override, system-prompt disclosure) are
# built from named fragments so their synonym coverage stays readable and
# auditable instead of being buried in one unreadable regex.

# Verbs that cancel or set aside earlier instructions.
_OVERRIDE_VERB = (r"(?:ignore|disregard|forget|discard|drop|delete|erase|omit|skip|"
                  r"bypass|override|throw\s+away|set\s+aside|pay\s+no\s+attention\s+to|"
                  r"do\s+not\s+follow|don'?t\s+follow)")
# Words marking "what came before" (the thing being overridden).
_EARLIER = (r"(?:previous|prior|above|earlier|preceding|foregoing|original|initial|"
            r"former|existing|system)")
# Nouns for the instructions themselves.
_DIRECTIVE = (r"(?:instructions?|directives?|directions?|commands?|rules?|guidelines?|"
              r"prompts?|constraints?|orders?|messages?|restrictions?)")

# Verbs used to ask the model to emit its own system prompt.
_DISCLOSE = (r"(?:reveal|show|print|repeat|output|display|disclose|divulge|expose|leak|"
             r"dump|echo|paste|recite|share|write\s+out|spell\s+out|tell\s+me|give\s+me|"
             r"send\s+me|reply\s+with|respond\s+with)")
# The disclosure target. Requires either a possessive ("your instructions") or a
# system-ish qualifier ("the hidden prompt"), so ordinary phrasings such as
# "show me the instructions" (for a product, a recipe, a form) do not match.
_PROMPT_TARGET = (r"(?:(?:your|the)\s+(?:system|initial|original|hidden|secret|internal|"
                  r"underlying|full|exact|verbatim|complete)\s+"
                  r"(?:prompt|instructions?|directives?|message|rules?|configuration)"
                  r"|your\s+(?:prompt|instructions?|directives?|system\s+message))")

# (regex, human-readable label, weight)  — labels are shown to users; patterns are not.
_PATTERNS: List[Tuple[str, str, float]] = [
    # --- Family 1: override the earlier instructions ---
    # Covers the synonym space of "ignore all previous instructions": ignore /
    # disregard / forget / discard / throw away / bypass ... previous | prior |
    # above | earlier | original ... instructions | rules | directives | commands.
    (rf"{_OVERRIDE_VERB}\s+(?:(?:all|any|every|the|your|these|those|of)\s+){{0,3}}"
     rf"{_EARLIER}\s+(?:\w+\s+){{0,2}}{_DIRECTIVE}",
     "ignore previous instructions", 0.9),
    # Same family without a directive noun: "forget everything you were told",
    # "ignore anything above".
    (rf"{_OVERRIDE_VERB}\s+(?:everything|anything|all)\b[^.\n]{{0,20}}"
     r"(?:above|before|prior|previous(?:ly)?|earlier|"
     r"you\s+(?:were\s+told|have\s+been\s+told|read|saw))",
     "ignore all prior context", 0.9),
    (r"disregard\s+(the\s+)?(above|previous|system)", "disregard the above", 0.8),
    # TR patterns are diacritic-tolerant: match both "onceki tum" and "önceki tüm".
    (r"[öo]nceki\s+(t[üu]m\s+)?(talimatlar[ıi]|komutlar[ıi])\s+(yoksay|g[öo]zard[ıi]|unut)", "ignore previous instructions (TR)", 0.9),

    # --- Family 2: make the model disclose its system prompt ---
    (rf"{_DISCLOSE}\b[^.\n]{{0,30}}{_PROMPT_TARGET}",
     "reveal the system prompt", 0.9),
    # Question form of the same probe: "what are your instructions?".
    (r"\bwhat\s+(?:is|are|was|were)\s+(?:your|the)\s+"
     r"(?:system\s+|initial\s+|original\s+|hidden\s+)?(?:prompt|instructions)\b",
     "probe for the system prompt", 0.85),
    (r"(reveal|show|print|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions)", "reveal the system prompt", 0.9),
    # TR "reveal / leak the system prompt".
    (r"sistem\s+prompt\w*.{0,20}(g[öo]ster|if[şs]a|s[ıi]zd[ıi]r|yazd[ıi]r|payla[şs])", "reveal the system prompt (TR)", 0.9),
    (r"sistem\s+prompt", "reference to system prompt", 0.6),

    # --- Family 3: role / persona jailbreaks ---
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
                if label not in matches:          # the same family may fire twice
                    matches.append(label)
                max_w = max(max_w, w)
        triggered = max_w >= self.block_score
        if matches:
            reason = f"{len(matches)} known injection/jailbreak pattern(s) matched."
        else:
            reason = "No known injection pattern found."
        return Detection(self.name, triggered, round(max_w, 2), reason, matches)
