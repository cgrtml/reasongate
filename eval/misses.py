"""What the rule core misses, on real attack prompts, grouped so it can be acted on.

RESULTS.md reports that naturally-phrased attacks get past the core. That is one
number and it does not say *which* attacks or *why*, so it cannot drive a design
decision. This script takes the cached real set (`eval/data/real.json`, the
deepset/prompt-injections corpus), runs the core over every labeled attack, and
reports the misses three ways: by language, by attack shape, and as a side-by-side
of near-identical phrasings where one blocks and one does not.

Everything here comes from the labeled corpus. Nothing is written for the occasion,
including the examples printed at the end; they are dataset rows, quoted.

  python -m eval.misses          # (or: PYTHONPATH=. python eval/misses.py)

Fully offline. Measures the rule core only: the ML add-on is a separate package
and is off by default in any case (see RESULTS.md on its over-defense).
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reasongate import Shield

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "real.json")

# Crude language split. The corpus is a German/English parallel set, so a stopword
# and umlaut count separates it well enough to report a per-language recall; it is
# not a language identifier and is not used for anything else.
_DE = re.compile(r"\b(und|nicht|eine|ich|sie|dich|deine|alle|jetzt|folgende|vorherigen|"
                 r"Aufgabe|warum|wie|das|der|die|ist|bitte|vergiss|ignoriere)\b", re.I)

# Attack shapes, matched in order; the first hit wins. These are descriptive labels
# for reading the misses, not detectors; a prompt that matches nothing lands in the
# last bucket, which is the interesting one.
SHAPES: List[Tuple[str, str]] = [
    ("act-as utility prompt (label suspect)",
     r"\b(act as|fungieren|i want you to act as|ich möchte, dass sie als)\b"),
    ("persona / roleplay framing",
     r"\b(you are now|now you are|pretend|imagine you|jetzt bist du|du bist|"
     r"stell dir vor|are two actors|schauspieler|in their roles|in ihren rollen)\b"),
    ("prompt-leak request",
     r"\b(prompt|instructions|anweisungen|system message)\b.{0,40}\b(show|reveal|repeat|"
     r"print|display|zeige|vorzeigen)\b|\b(show|zeige|vorzeigen)\b.{0,40}"
     r"\b(prompt|anweisungen)\b|written at the beginning"),
    ("instruction reset, politeness-wrapped",
     r"\b(forget|vergiss|leave .{0,20}behind|lassen sie .{0,30}hinter|start over|"
     r"von vorne|start from the front|new task|neue aufgabe|neue anweisungen|"
     r"new instructions|remove all previous|aus dem kopf)\b"),
    ("override verb without an object noun",
     r"\b(ignore|ignorier\w*|disregard)\b"),
]


def load() -> List[Tuple[str, int]]:
    if not os.path.exists(DATA):
        print(f"Missing {DATA}. Run `python eval/fetch_real.py` once to cache the\n"
              "corpus; this script stays offline and will not fetch on its own.",
              file=sys.stderr)
        raise SystemExit(2)
    with open(DATA, encoding="utf-8") as fh:
        blob = json.load(fh)
    rows = blob.get("train", []) + blob.get("test", []) if isinstance(blob, dict) else blob
    return [(t, int(l)) for t, l in rows if isinstance(t, str) and t]


def german(text: str) -> bool:
    return len(_DE.findall(text)) >= 3 or len(re.findall(r"[äöüßÄÖÜ]", text)) >= 2


def shape(text: str) -> str:
    for label, pattern in SHAPES:
        if re.search(pattern, text, re.I):
            return label
    return "no marker the core looks for"


def main() -> None:
    rows = load()
    shield = Shield()
    attacks = [t for t, l in rows if l == 1]
    benign = [t for t, l in rows if l == 0]

    verdicts = {t: shield.scan_input(t).action for t in attacks}
    missed = [t for t in attacks if verdicts[t] != "block"]
    blocked = [t for t in attacks if verdicts[t] == "block"]
    fp = [t for t in benign if shield.scan_input(t).action == "block"]

    print(f"\nCorpus: {len(attacks)} labeled attacks, {len(benign)} labeled benign "
          f"(deepset/prompt-injections, cached)\n")
    print(f"  blocked          {len(blocked):4d} / {len(attacks)}  "
          f"({100 * len(blocked) / len(attacks):.1f}% recall)")
    print(f"  missed           {len(missed):4d} / {len(attacks)}")
    print(f"  false positives  {len(fp):4d} / {len(benign)}  "
          f"({100 * len(fp) / len(benign):.1f}% FPR)")

    print("\n--- Recall by language ---")
    by_lang: Dict[str, List[int]] = {}
    for t in attacks:
        slot = by_lang.setdefault("German" if german(t) else "English", [0, 0])
        slot[0] += 1
        slot[1] += verdicts[t] == "block"
    for lang, (n, hit) in sorted(by_lang.items()):
        print(f"  {lang:8} {hit:4d} / {n:4d}  ({100 * hit / n:.1f}%)")

    print("\n--- Recall by attack shape (blocked / total, and share of all misses) ---")
    tot: Dict[str, int] = {}
    hit: Dict[str, int] = {}
    for t in attacks:
        label = shape(t)
        tot[label] = tot.get(label, 0) + 1
        hit[label] = hit.get(label, 0) + (verdicts[t] == "block")
    for label in sorted(tot, key=lambda k: -(tot[k] - hit[k])):
        gap = tot[label] - hit[label]
        print(f"  {hit[label]:3d} / {tot[label]:3d}  ({100 * hit[label] / tot[label]:5.1f}% recall)"
              f"   {gap:3d} misses = {100 * gap / len(missed):4.1f}% of all   {label}")

    print("\n--- Same intent, opposite verdict (quoted from the corpus) ---")
    # Restrict the contrast to rows that carry an override or reset marker, so the
    # pairs differ in wording or language rather than in what they are trying to do.
    marked = re.compile(r"\b(ignore|ignorier\w*|disregard|forget|vergiss|"
                        r"vorherigen|previous|preceding|abweichend)\b", re.I)
    pick = lambda pool, de: sorted((t for t in pool if marked.search(t) and german(t) is de),
                                   key=len)[:3]
    short_blocked = pick(blocked, False)[:2]
    short_missed_en = pick(missed, False)
    short_missed_de = pick(missed, True)
    for t in short_blocked + short_missed_en + short_missed_de:
        r = shield.scan_input(t)
        flat = " ".join(t.split())
        print(f"  {r.action:5} {r.risk_score:4.2f}  {flat[:88]}")

    print("\nRead the last block together with the language table: the German rows are\n"
          "translations of shapes the core blocks in English, so a share of what reads\n"
          "as a phrasing gap is a language gap. See docs/coverage-gaps.md.\n")


if __name__ == "__main__":
    main()
