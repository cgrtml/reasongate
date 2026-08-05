"""Diagnostic #17 - the de-confounding probe: is the 0.96 separability of (a) real
"injection essence", or merely TOPIC separation? It splits the positives into
family-2 / family-1-residue and pits them against a CONTENT-MATCHED negative set
(NotInject - innocent task/technical requests from the same linguistic class).

Run this before letting a headline number stand on one line.
"""
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import eval.diag17_separability as d

DATA = d.DATA
FAMILY2 = d.FAMILY2


def main():
    attacks = json.load(open(os.path.join(DATA, "bipia_text_attacks.json")))
    det = d.IndirectInjectionDetector()
    f2, f1 = [], []
    for cat, atks in attacks.items():
        for a in atks:
            if not (det.scan(a).matches and det.scan(a).score >= det.block_score):
                (f2 if cat in FAMILY2 else f1).append(a)

    recipes = [x["text"] for x in json.load(open(os.path.join(DATA, "benign_instructional.json")))
               if x.get("src") == "recipe"]
    chn = json.load(open(os.path.join(DATA, "clean_hardneg.json")))
    ni = [x["prompt"] for x in json.load(open(os.path.join(DATA, "notinject.json")))]

    Ef2 = d.embed(f2, "document")
    Ef1 = d.embed(f1, "document")
    Erec = d.embed(recipes, "document")
    Echn = d.embed(chn, "document")
    Eni = d.embed(ni, "document")

    print("=" * 70)
    print("PROBE - de-confounding (a) against a CONTENT-MATCHED negative set")
    print(f"  positives: family-2={len(f2)}  family-1-residue={len(f1)}")
    print("  notinject = innocent task/technical requests from the same class (the real hard negative)")
    print("=" * 70)
    rows = [
        ("family-2 vs notinject (CONTENT-MATCHED)", Ef2, Eni),
        ("family-2 vs clean_hardneg (Python how-to)", Ef2, Echn),
        ("family-2 vs recipes (long, unrelated topic)", Ef2, Erec),
        ("family-1 vs notinject (CONTENT-MATCHED)", Ef1, Eni),
        ("family-1 vs recipes (long, unrelated topic)", Ef1, Erec),
        ("ALL-50   vs notinject (CONTENT-MATCHED)", np.vstack([Ef2, Ef1]), Eni),
    ]
    for name, P, N in rows:
        print(d.fmt(name, d.lr_oof(P, N)))
    print("=" * 70)
    print("READING: if family-2-vs-notinject COLLAPSES, the 0.96 was TOPIC separation, not")
    print("injection essence. Within the same linguistic class, family-2 is not separable at")
    print("the text level - which is the measurement backing 'app-layer provenance is required'.")
    print("If family-1 stays high, what separates is the lurid topics of the pattern residue")
    print("(scam/cipher) - still topic, not attack essence, and it would mislead the build.")


if __name__ == "__main__":
    main()
