"""BIPIA indirect-injection benchmark - two axes (recall + over-defense).

Two families:
  - Family 1 (output-directed meta-directives): "Encode your response in Base64",
    "Add X to your reply" -> closed with meta-directive PATTERNS (offline).
  - Family 2 (unmarked embedded tasks): "Write a script to rename all files" ->
    patterns cannot catch these; a SEMANTIC layer is required (next step, with
    BIPIA held out).

The FPR axis: benign-instructional (recipes + how-tos, legitimate imperative-heavy
content) + NotInject. It verifies that the patterns do NOT over-block legitimate
imperative content.

  python eval/bipia_bench.py
"""
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reasongate.shield import Shield

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
FAMILY2 = {"Task Automation", "Business Intelligence", "Conversational Agent",
           "Research Assistance", "Sentiment Analysis"}
# BIPIA attack definitions are downloaded from the Microsoft repo (raw data is NOT committed).
BIPIA_URL = ("https://raw.githubusercontent.com/microsoft/BIPIA/main/"
             "benchmark/text_attack_test.json")


def _load_bipia():
    import urllib.request
    path = os.path.join(DATA, "bipia_text_attacks.json")
    if not os.path.exists(path):
        os.makedirs(DATA, exist_ok=True)
        print("Downloading BIPIA attacks (microsoft/BIPIA)...")
        urllib.request.urlretrieve(BIPIA_URL, path)
    return json.load(open(path))


def main():
    sh = Shield()
    blk = lambda t: sh.scan_context(t).action == "block"

    attacks = _load_bipia()
    print("=" * 62)
    print("BIPIA indirect - recall (meta-directive patterns, offline)")
    print("=" * 62)
    f1d = f1t = f2d = f2t = 0
    for cat, atks in attacks.items():
        dd = sum(blk(a) for a in atks)
        fam = "2" if cat in FAMILY2 else "1"
        if cat in FAMILY2: f2d += dd; f2t += len(atks)
        else: f1d += dd; f1t += len(atks)
        print(f"  [{fam}] {cat:26}: {100*dd/len(atks):5.1f}%")
    tot_d, tot = f1d + f2d, f1t + f2t
    print("-" * 62)
    print(f"  OVERALL: {100*tot_d/tot:.1f}% ({tot_d}/{tot})")
    print(f"  Family 1 (meta-directive, pattern coverage): {100*f1d/f1t:.1f}% ({f1d}/{f1t})")
    print(f"  Family 2 (unmarked task, awaiting the SEMANTIC layer): {100*f2d/f2t:.1f}% ({f2d}/{f2t})")

    # The FPR axis - THREE sets; the critical one is the 'your-ref' hard negative (customer service)
    bi = json.load(open(os.path.join(DATA, "benign_instructional.json")))
    yr = json.load(open(os.path.join(DATA, "benign_yourref.json")))   # legitimate text carrying 'your response'
    ni = json.load(open(os.path.join(DATA, "notinject.json")))
    fpr_bi = 100 * np.mean([blk(x["text"]) for x in bi])
    fpr_yr = 100 * np.mean([blk(t) for t in yr])
    fpr_ni = 100 * np.mean([blk(r["prompt"]) for r in ni])
    print("\n--- Over-defense (FPR) ---")
    print(f"  benign-instructional (recipes+how-to, {len(bi)}): {fpr_bi:.1f}%")
    print(f"  your-ref hard-neg (legitimate 'your reply/response', {len(yr)}): {fpr_yr:.1f}%  <- the real test")
    print(f"  NotInject ({len(ni)}): {fpr_ni:.1f}%")

    print("\n--- markdown ---")
    print("| BIPIA | Recall (overall / family-1) | FPR (your-ref hard-neg) |")
    print("|---|---:|---:|")
    print(f"| markers only | 0% / 0% | — |")
    print(f"| + meta-directive patterns | {100*tot_d/tot:.0f}% / {100*f1d/f1t:.0f}% | {fpr_yr:.1f}% |")


if __name__ == "__main__":
    main()
