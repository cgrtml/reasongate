"""Diagnostic #17 - PROVENANCE evaluated at the DECISION level, mixed trust.

Provenance is a PRIOR, not a discriminator, so a signal-level AUC is MEANINGLESS
(see the spec). Its value can only be shown at the DECISION level
(allow/flag/block). Three components:
  1. user-trusted imperative text (the WEDGE): provenance must STAY SILENT ->
     ~100% allow.
  2. untrusted benign retrieved content (the over-defense cost): after the full
     fusion stack, is it allow/flag/block? CAP_PROV is DERIVED from this row.
  3. untrusted injected content (the benefit): does the block rate rise versus cap=0?

CAP_PROV SWEEP: off/0.3/0.35/0.5. No embeddings, offline, fast.
Output: a decision-level table used to calibrate CAP_PROV.
"""
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reasongate.shield import Shield
from reasongate.types import Segment
from reasongate.detectors.indirect import IndirectInjectionDetector

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
FAMILY2 = {"Task Automation", "Business Intelligence", "Conversational Agent",
           "Research Assistance", "Sentiment Analysis"}
CAPS = [0.0, 0.30, 0.35, 0.50]


def load():
    bi = json.load(open(os.path.join(DATA, "benign_instructional.json")))
    benign = [x["text"] for x in bi]                       # 305 (recipes + how-to)
    yr = list(json.load(open(os.path.join(DATA, "benign_yourref.json"))))   # 20 wedge
    attacks = json.load(open(os.path.join(DATA, "bipia_text_attacks.json")))
    det = IndirectInjectionDetector()
    payloads, fam = [], []
    for cat, atks in attacks.items():
        for a in atks:
            if not (det.scan(a).matches and det.scan(a).score >= det.block_score):
                payloads.append(a); fam.append(2 if cat in FAMILY2 else 1)
    recipes = [x["text"] for x in bi if x.get("src") == "recipe"]
    return benign, yr, payloads, fam, recipes


def rates(shield, segments):
    """Run each segment through scan_context on its own; return the action distribution."""
    c = Counter(shield.scan_context([s]).action for s in segments)
    n = sum(c.values())
    return {k: 100.0 * c.get(k, 0) / n for k in ("allow", "flag", "block")}, n


def fmt_row(label, r):
    return (f"  {label:34} allow {r['allow']:5.1f}  flag {r['flag']:5.1f}  "
            f"block {r['block']:5.1f}")


def main():
    benign, yr, payloads, fam, recipes = load()
    # the segment sets
    # 1) WEDGE: the user pasted their own imperative text (same recipe text, trust=user)
    trusted = [Segment(t, source="user", trust="trusted") for t in recipes]
    # 2) over-defense: benign retrieved content (recipes+how-to) + your-ref, untrusted
    untrusted_benign = [Segment(t, source="retrieved", trust="untrusted") for t in benign]
    untrusted_yr = [Segment(t, source="retrieved", trust="untrusted") for t in yr]
    # 3) benefit: payload embedded in a legitimate recipe host, untrusted (the real
    #    indirect-injection scenario)
    injected = [Segment(recipes[i % len(recipes)] + "\n" + p, source="retrieved",
                        trust="untrusted")
                for i, p in enumerate(payloads)]
    inj_f2 = [s for s, f in zip(injected, fam) if f == 2]
    inj_f1 = [s for s, f in zip(injected, fam) if f == 1]

    print("=" * 74)
    print("PROVENANCE - decision level, mixed trust (CAP_PROV sweep, retrieved source)")
    print("  the retrieved source weight is 0.8 -> effective score = CAP x 0.8")
    print("=" * 74)

    for cap in CAPS:
        sh = Shield(provenance_cap=cap)
        tag = "OFF (baseline)" if cap == 0.0 else f"CAP={cap}"
        print(f"\n--- {tag} ---")
        r, n = rates(sh, trusted)
        print(fmt_row(f"1 WEDGE user-trusted imperative ({n})", r) +
              ("   <- must be ~100 allow" if cap > 0 else ""))
        r, _ = rates(sh, untrusted_benign)
        print(fmt_row(f"2 untrusted benign recipe/howto", r) + "   <- the over-defense cost")
        r, _ = rates(sh, untrusted_yr)
        print(fmt_row(f"2 untrusted your-ref wedge", r))
        rf2, _ = rates(sh, inj_f2)
        rf1, _ = rates(sh, inj_f1)
        print(fmt_row(f"3 injected FAMILY-2 ({len(inj_f2)})", rf2) + "   <- the benefit (the real target)")
        print(fmt_row(f"3 injected family-1 ({len(inj_f1)})", rf1))

    # --- WHY IT IS FLAT: the second-signal frequency (fusion needs a co-signal) ---
    from reasongate.policy import fuse, FUSION_FLOOR
    idet = IndirectInjectionDetector()

    def s2_freq(segs):
        sc = [idet.scan(s.text).score for s in segs]
        return (100.0 * sum(x >= FUSION_FLOOR for x in sc) / len(sc),
                100.0 * sum(x >= 0.5 for x in sc) / len(sc), max(sc))

    print("\n" + "=" * 74)
    print("WHY IT IS FLAT - SECOND-SIGNAL frequency (IndirectInjectionDetector, live stack)")
    print("=" * 74)
    for name, segs in [("untrusted benign", untrusted_benign),
                       ("injected FAMILY-2", inj_f2), ("injected family-1", inj_f1)]:
        f30, f50, mx = s2_freq(segs)
        print(f"  {name:20}: score>=0.30 {f30:.1f}%  >=0.50 {f50:.1f}%  max={mx:.2f}")
    print("  -> the residue (family-2 especially) does not trip a second signal, so")
    print("     provenance has NO co-signal to fuse with -> sub-flag alone -> INERT.")

    print("\n" + "=" * 74)
    print("INTERACTION TABLE - fuse(provenance=CAPx0.8, second signal s2) -> action")
    print("  (this is where provenance has VALUE: how it shifts the decision when a")
    print("   co-signal IS present)")
    print("=" * 74)

    def act(f):
        return "BLOCK" if f >= 0.8 else ("flag" if f >= 0.5 else "allow")
    s2s = [0.0, 0.30, 0.50, 0.60, 0.70]
    print(f"  {'CAP(eff)':>10} | " + " ".join(f"s2={s:>4}" for s in s2s))
    for cap in CAPS:
        eff = round(cap * 0.8, 2)
        cells = []
        for s2 in s2s:
            scores = [x for x in (eff, s2) if x >= FUSION_FLOOR]
            cells.append(f"{act(fuse([eff, s2])):>6}")
        print(f"  {eff:>10} | " + " ".join(cells))
    print("  READING: with no co-signal (s2=0) every CAP allows (NO over-defense).")
    print("  With a co-signal of 0.6-0.7, provenance shifts the decision to flag/BLOCK")
    print("  - that is the benefit. Calibration: s2>=0.3 is rare on benign content")
    print("  (see above), so the back-door risk is low; CAP_PROV should be the highest")
    print("  value that carries a REAL attack with a co-signal to block without")
    print("  co-flagging benign content. Host incoherence (archived) is the natural")
    print("  co-signal candidate.")
    print("=" * 74)


if __name__ == "__main__":
    main()
