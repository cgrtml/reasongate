"""Diagnostic #17 - the MIXED-CHUNK test (the blind spot of the earlier diagnostic).

cos_max was measured on ISOLATED payloads (chunk = the attack). A real indirect
injection payload arrives EMBEDDED inside a LEGITIMATE HOST document. In that
chunk the host's own legitimate imperatives are aligned with the user, so cos_max
is high and the injection is masked.

Setup: the same host and the same user prompt, toggling the injection on and off
(host + prompt fixed, only the payload changes). Two measurements:
  (A) does the current cos_max COLLAPSE on this set? (prediction: yes -> the 0.854
      was an artifact of isolation)
  (B) span conjunction: for each span, (user misalignment u, host incoherence h).
      u = 1-cos(span, user); h = 1-cos(span, the OTHER sentences of the same chunk,
      leave-one-out). An embedded payload has high u AND high h. "Take off heat"
      has high u but LOW h (it is host-coherent), so it is filtered out. The chunk
      score is max_span(u*h). The wedge is recipe + your-ref.
"""
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import eval.diag17_separability as d
from reasongate.detectors.imperative import extract_imperative_spans, _split_sentences

DATA = d.DATA
N_HOST = 100   # number of recipe hosts (cost control)


def main():
    attacks = json.load(open(os.path.join(DATA, "bipia_text_attacks.json")))
    FAMILY2 = d.FAMILY2
    det = d.IndirectInjectionDetector()
    payloads, pay_fam = [], []
    for cat, atks in attacks.items():
        for a in atks:
            if not (det.scan(a).matches and det.scan(a).score >= det.block_score):
                payloads.append(a); pay_fam.append(2 if cat in FAMILY2 else 1)
    recipes = [x["text"] for x in json.load(open(os.path.join(DATA, "benign_instructional.json")))
               if x.get("src") == "recipe"][:N_HOST]
    yr = list(json.load(open(os.path.join(DATA, "benign_yourref.json"))))

    # --- build the chunks: (user_prompt, chunk_text, label, kind) ---
    # host + prompt FIXED, injection toggled. The user prompt is a LOOSE food
    # question, which is the honest choice.
    chunks = []
    for i, r in enumerate(recipes):
        up = d.FOOD_LOOSE[i % len(d.FOOD_LOOSE)]
        body = d.directions_span(r)
        chunks.append((up, body, 0, "clean_recipe"))                       # clean host
        pay = payloads[i % len(payloads)]; fam = pay_fam[i % len(payloads)]
        kind = "injected_f2" if fam == 2 else "injected_f1"
        chunks.append((up, body + "\n" + pay, 1, kind))                    # host + embedded payload
    for i, t in enumerate(yr):                                             # wedge: single-span benign
        chunks.append((d.YR_LOOSE[i % len(d.YR_LOOSE)], t, 0, "clean_yourref"))

    # --- embedding: every sentence (for LOO host coherence) + the prompts ---
    all_sents, all_prompts = set(), set()
    for up, ch, lab, kind in chunks:
        all_prompts.add(up)
        for s in _split_sentences(ch):
            all_sents.add(s)
    all_sents = list(all_sents); all_prompts = list(all_prompts)
    Es = dict(zip(all_sents, d.embed(all_sents, "document")))
    Pq = dict(zip(all_prompts, d.embed(all_prompts, "query")))

    def cos1(a, b):
        a = a / (np.linalg.norm(a) + 1e-9); b = b / (np.linalg.norm(b) + 1e-9)
        return float(a @ b)

    # payload gate coverage per family: is the payload imperative-form ON ITS OWN?
    cov2 = [extract_imperative_spans(p) != [] for p, f in zip(payloads, pay_fam) if f == 2]
    cov1 = [extract_imperative_spans(p) != [] for p, f in zip(payloads, pay_fam) if f == 1]

    rows = []   # (label, kind, cos_max, max_u, max_h, max_uh, max_min)
    for up, ch, lab, kind in chunks:
        sents = _split_sentences(ch)
        gated = extract_imperative_spans(ch)
        if not gated:
            gated = [ch.strip()]
        qv = Pq[up]
        cos_max = -1.0; mu = mh = muh = mmin = 0.0
        for g in gated:
            cu = cos1(Es.get(g, qv*0), qv)             # span-user cosine
            cos_max = max(cos_max, cu)
            u = 1.0 - cu                                # user misalignment
            others = [Es[s] for s in sents if s != g]
            if others:
                hc = np.mean(others, axis=0)
                h = 1.0 - cos1(Es.get(g, hc*0), hc)    # host incoherence (leave-one-out)
            else:
                h = 0.0                                 # a single span cannot be incoherent
            muh = max(muh, u * h); mmin = max(mmin, min(u, h))
            mu = max(mu, u); mh = max(mh, h)
        rows.append((lab, kind, cos_max, mu, mh, muh, mmin))

    kinds = np.array([r[1] for r in rows])
    R = np.array([(l, cm, u, h, uh, mn) for l, k, cm, u, h, uh, mn in rows])
    yall = R[:, 0]
    clean_mask = yall == 0
    print("=" * 70)
    print("MIXED-CHUNK - host+embedded payload vs clean host (host+prompt FIXED)")
    print("=" * 70)
    nf2 = int((kinds == "injected_f2").sum()); nf1 = int((kinds == "injected_f1").sum())
    print(f"chunks: {nf2} injected_f2 + {nf1} injected_f1 + {int(clean_mask.sum())} clean "
          f"({len(recipes)} recipe + {len(yr)} your-ref)")
    print(f"payload GATE COVERAGE (imperative form): family-2 {sum(cov2)}/{len(cov2)}  "
          f"family-1 {sum(cov1)}/{len(cov1)}  <- a coverage limit, named not hidden")

    def auc_vs_clean(pos_kind, col, hi=True):
        m = clean_mask | (kinds == pos_kind)
        s = R[m, col] if hi else -R[m, col]
        return d.auc_ci(R[m, 0], s)

    print("\n[AUC - injected vs clean]  (FAMILY-2 is the real target of #17)")
    for tag, kind in [("FAMILY-2", "injected_f2"), ("family-1", "injected_f1")]:
        print(f"  -- {tag} --")
        print(d.fmt("   (A) cos_max  [0.854 when ISOLATED]", auc_vs_clean(kind, 1, hi=False)))
        print(d.fmt("       max_u  (user misalignment)", auc_vs_clean(kind, 2)))
        print(d.fmt("       max_h  (host incoherence)", auc_vs_clean(kind, 3)))
        print(d.fmt("   (B) max(u*h)  CONJUNCTION", auc_vs_clean(kind, 4)))

    # wedge: clean recipe vs injected-f2
    rc = R[kinds == "clean_recipe"]; ri = R[kinds == "injected_f2"]
    yrr = R[kinds == "clean_yourref"]
    print("\n[confound / wedge check - medians, family-2]")
    print(f"  cos_max:  clean-recipe={np.median(rc[:,1]):.3f}  "
          f"injected-f2={np.median(ri[:,1]):.3f}  (if these are close, cos_max COLLAPSED)")
    print(f"  max_h:    clean-recipe={np.median(rc[:,3]):.3f}  "
          f"injected-f2={np.median(ri[:,3]):.3f}  (FP risk: the recipe h floor)")
    print(f"  u*h:      clean-recipe={np.median(rc[:,4]):.3f}  "
          f"injected-f2={np.median(ri[:,4]):.3f}  your-ref={np.median(yrr[:,4]):.3f}")

    print("\n[READING]")
    print("  If (A) cos_max collapses (~0.5) while (B) u*h separates (>>0.5), the spec")
    print("  becomes a span conjunction and the build aims at the right target.")
    print("  If (B) collapses too: this is the chunk-level ceiling -> app-layer")
    print("  provenance is MANDATORY.")
    print("=" * 70)


if __name__ == "__main__":
    main()
