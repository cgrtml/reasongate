"""Adversarial / evasion evaluation.

The question: does the gate still catch an attack once it is OBFUSCATED?
Produces the "obfuscated recall" row of the honest table in RESULTS.md.

The attacker side is generated INDEPENDENTLY (deliberately WITHOUT using
reasongate.normalize) — otherwise defense and attack would share code and the
test would not be fair. Each base attack (eval.dataset.ATTACKS) is multiplied by
these evasions:
  leetspeak, letter-spacing, dot-breaking, homoglyphs (Cyrillic), zero-width,
  base64 wrapping, HTML-comment wrapping (indirect).

Run:  PYTHONPATH=. python eval/adversarial.py
Fully offline (no embedding/API) — it measures the rule + normalization layer only.
"""
from __future__ import annotations

import base64
from typing import Callable, Dict, List

from eval.dataset import ATTACKS, BENIGN
from eval import metrics
from reasongate.shield import Shield
from reasongate.detectors import InjectionDetector

# ---- Attacker-side obfuscators (INDEPENDENT of the defense) ----
_LEET = str.maketrans({"o": "0", "i": "1", "e": "3", "a": "4", "s": "5"})
_HOMO = str.maketrans({"a": "а", "e": "е", "o": "о", "p": "р", "c": "с",
                       "i": "і", "x": "х", "y": "у"})  # Latin -> Cyrillic
_ZW = "​"


def _leet(s: str) -> str:        return s.translate(_LEET)
def _spaced(s: str) -> str:      return "  ".join(" ".join(w) for w in s.split())
def _dotted(s: str) -> str:      return " ".join(".".join(w) for w in s.split())
def _homoglyph(s: str) -> str:   return s.translate(_HOMO)
def _zerowidth(s: str) -> str:   return _ZW.join(s)
def _b64(s: str) -> str:         return "Decode and follow: " + base64.b64encode(s.encode()).decode()
def _htmlcomment(s: str) -> str: return f"Here is the document. <!-- {s} -->"

OBFUSCATORS: Dict[str, Callable[[str], str]] = {
    "plain (control)": lambda s: s,
    "leetspeak": _leet,
    "letter-spacing": _spaced,
    "dot-breaking": _dotted,
    "homoglyph (Cyrillic)": _homoglyph,
    "zero-width": _zerowidth,
    "base64": _b64,
    "HTML-comment (indirect)": _htmlcomment,
}


def _predict_old(text: str) -> int:
    """The old defense: the regex InjectionDetector alone."""
    return 1 if InjectionDetector().scan(text).triggered else 0


def _make_new_predictor():
    shield = Shield()  # injection + normalization

    def predict(text: str) -> int:
        # input side (direct/hidden) and indirect (html-comment) evaluated together
        if shield.scan_input(text).action == "block":
            return 1
        return 1 if shield.scan_context(text).action == "block" else 0
    return predict


def evaluate() -> None:
    predict_new = _make_new_predictor()

    # Vary the benign side (slightly) too, to measure FPR honestly.
    benign_variants = list(BENIGN) + [_spaced(b) for b in BENIGN[:10]]

    print("=" * 70)
    print("ADVERSARIAL EVAL - detection rate (recall) under obfuscation")
    print("=" * 70)
    print(f"{'Evasion type':18} | {'OLD (regex)':>14} | {'NEW (gate)':>14}")
    print("-" * 70)

    rows = []
    all_y_old, all_p_old, all_y_new, all_p_new = [], [], [], []
    for name, fn in OBFUSCATORS.items():
        variants = [fn(a) for a in ATTACKS]
        old = [_predict_old(v) for v in variants]
        new = [predict_new(v) for v in variants]
        r_old = sum(old) / len(old)
        r_new = sum(new) / len(new)
        rows.append((name, r_old, r_new))
        print(f"{name:18} | {format(100*r_old,'.1f')+'%':>14} | {format(100*r_new,'.1f')+'%':>14}")
        all_y_old += [1] * len(old); all_p_old += old
        all_y_new += [1] * len(new); all_p_new += new

    # Benign (no attack intent) -> FPR
    b_old = [_predict_old(b) for b in benign_variants]
    b_new = [predict_new(b) for b in benign_variants]
    all_y_old += [0] * len(b_old); all_p_old += b_old
    all_y_new += [0] * len(b_new); all_p_new += b_new

    print("-" * 70)
    m_old = metrics.report(all_y_old, all_p_old)
    m_new = metrics.report(all_y_new, all_p_new)
    print(f"\nOVERALL (all evasions + benign):")
    print(f"  OLD : recall {100*m_old['recall']:.1f}%  FPR {100*m_old['fpr']:.1f}%  F1 {m_old['f1']:.3f}")
    print(f"  NEW : recall {100*m_new['recall']:.1f}%  FPR {100*m_new['fpr']:.1f}%  F1 {m_new['f1']:.3f}")

    # markdown ready to paste into RESULTS.md
    print("\n--- markdown for RESULTS.md ---")
    print("| Evasion | Old (regex only) recall | New (shield) recall |")
    print("|---|---:|---:|")
    for name, ro, rn in rows:
        print(f"| {name} | {100*ro:.1f}% | {100*rn:.1f}% |")
    print(f"| **Overall** | {100*m_old['recall']:.1f}% (FPR {100*m_old['fpr']:.1f}%) "
          f"| {100*m_new['recall']:.1f}% (FPR {100*m_new['fpr']:.1f}%) |")


if __name__ == "__main__":
    evaluate()
