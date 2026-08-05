"""Diagnostic #17 - intermediate measurement: GATED cosine.

Re-measures (b) using only the spans that pass the imperative-form gate. The 0.72
in the earlier diagnostic was a whole-chunk cosine; the gate removes the topic
noise and the length confound (injection 69 chars vs legitimate 217). This number
is the realistic build performance and gives the tau/lo/CAP calibration.
"""
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import eval.diag17_separability as d
from reasongate.detectors.imperative import extract_imperative_spans

DATA = d.DATA


def gated_spans(text):
    sp = extract_imperative_spans(text)
    return sp if sp else [text.strip()]   # fallback: empty gate -> the whole text (still counted)


def main():
    # --- positives (pattern residue) + negatives ---
    attacks = json.load(open(os.path.join(DATA, "bipia_text_attacks.json")))
    det = d.IndirectInjectionDetector()
    pos = [a for cat, atks in attacks.items() for a in atks
           if not (det.scan(a).matches and det.scan(a).score >= det.block_score)]
    recipes = [x["text"] for x in json.load(open(os.path.join(DATA, "benign_instructional.json")))
               if x.get("src") == "recipe"]
    yr = list(json.load(open(os.path.join(DATA, "benign_yourref.json"))))

    # --- build the pairs: (prompt, chunk, label, layer) ---
    pairs = []
    for i, a in enumerate(pos):
        pairs.append((d.HOST_TASKS[i % len(d.HOST_TASKS)], a, 1, "inj"))
    for i, r in enumerate(recipes):
        title = r.splitlines()[0].strip()
        body = d.directions_span(r)
        pairs.append((f"How do I make {title}?", body, 0, "tight"))
        pairs.append((d.FOOD_LOOSE[i % len(d.FOOD_LOOSE)], body, 0, "loose"))
    for i, t in enumerate(yr):
        pairs.append((d.YR_LOOSE[i % len(d.YR_LOOSE)], t, 0, "loose"))

    # --- gate + embedding ---
    n_empty = 0
    per_span = []           # (cos, label)
    per_chunk = []          # (cmin, cmax, cmean, label, layer)
    all_prompts = list({p for p, _, _, _ in pairs})
    Pq = dict(zip(all_prompts, d.embed(all_prompts, "query")))
    # collect every span and embed them in one pass
    chunk_spans = []
    for p, ch, lab, lay in pairs:
        sp = extract_imperative_spans(ch)
        if not sp:
            n_empty += 1
            sp = [ch.strip()]
        chunk_spans.append((p, sp, lab, lay))
    flat = list({s for _, sp, _, _ in chunk_spans for s in sp})
    Es = dict(zip(flat, d.embed(flat, "document")))

    for p, sp, lab, lay in chunk_spans:
        qv = Pq[p][None, :]
        cs = d.cos(np.repeat(qv, len(sp), 0), np.array([Es[s] for s in sp]))
        for c in cs:
            per_span.append((c, lab))
        per_chunk.append((cs.min(), cs.max(), cs.mean(), lab, lay))

    # --- AUCs (inj=1 means LOW cosine; feature = -cos) ---
    ps = np.array(per_span)
    auc_span = d.auc_ci(ps[:, 1], -ps[:, 0])
    pc = np.array([(a, b, c, l) for a, b, c, l, _ in per_chunk])
    lay = np.array([x[4] for x in per_chunk])
    y = pc[:, 3]
    auc_min = d.auc_ci(y, -pc[:, 0])
    auc_mean = d.auc_ci(y, -pc[:, 2])
    auc_max = d.auc_ci(y, -pc[:, 1])
    # the loose layer (the most honest): inj vs loose chunks only
    msk = (lay == "inj") | (lay == "loose")
    auc_min_loose = d.auc_ci(y[msk], -pc[msk, 0])
    auc_mean_loose = d.auc_ci(y[msk], -pc[msk, 2])
    auc_max_loose = d.auc_ci(y[msk], -pc[msk, 1])

    print("=" * 70)
    print("INTERMEDIATE - GATED cosine (only spans passing the imperative-form gate)")
    print("=" * 70)
    cov = 100 * (1 - n_empty / len(pairs))
    print(f"gate coverage: {cov:.0f}% of chunks have >=1 imperative span "
          f"({n_empty}/{len(pairs)} empty -> whole-text fallback)")
    sl = lambda xs: int(np.median([len(s) for s in xs]))
    inj_sp = [s for p, sp, l, _ in chunk_spans if l == 1 for s in sp]
    leg_sp = [s for p, sp, l, _ in chunk_spans if l == 0 for s in sp]
    print(f"gated span char median: injection={sl(inj_sp)}  legit={sl(leg_sp)} "
          f"(it was 69 vs 217 in the diagnostic -> the length confound)")
    inj_c = np.array([a for a, _, _, l, ly in per_chunk if l == 1])
    loose_c = np.array([a for a, _, _, l, ly in per_chunk if l == 0 and ly == "loose"])
    print(f"cos_min median: injection={np.median(inj_c):.3f}  "
          f"loose-legit={np.median(loose_c):.3f} "
          f"(whole-chunk in the diagnostic: 0.248 vs 0.314)")

    print("\n[GATED AUC - inj vs legit]")
    print(d.fmt("per-SPAN (each imperative span is a unit)", auc_span))
    print(d.fmt("per-CHUNK  cos_min  (ALL legit)", auc_min))
    print(d.fmt("per-CHUNK  cos_mean (ALL legit)", auc_mean))
    print(d.fmt("per-CHUNK  cos_max  (ALL legit)", auc_max))
    print("  --- loose layer (inj vs LOOSE legit; the most honest build estimate) ---")
    print(d.fmt("per-CHUNK  cos_min  (loose)  [KILLS the wedge]", auc_min_loose))
    print(d.fmt("per-CHUNK  cos_mean (loose)", auc_mean_loose))
    print(d.fmt("per-CHUNK  cos_max  (loose)  [wedge-SAFE]", auc_max_loose))

    # cos_max = is there ANY imperative in the chunk aligned with what the user asked for.
    inj_mx = np.array([b for _, b, _, l, _ in per_chunk if l == 1])
    loose_mx = np.array([b for _, b, _, l, ly in per_chunk if l == 0 and ly == "loose"])
    print("\n[calibration - the detector must use cos_max (cos_min killed the wedge)]")
    tau = float(np.median(loose_mx)); lo = float(np.percentile(inj_mx, 75))
    print(f"  cos_max distribution: inj median={np.median(inj_mx):.3f} "
          f"p75={np.percentile(inj_mx,75):.3f} | loose-legit median={np.median(loose_mx):.3f}")
    print(f"  suggestion: tau~{tau:.2f} (loose-legit median), lo~{lo:.2f}; "
          f"score = CAP * clip((tau-cos_max)/(tau-lo),0,1), CAP=0.6")
    print(f"  REALISTIC BUILD ESTIMATE: gated loose cos_max AUC={auc_max_loose[0]:.3f} "
          f"[{auc_max_loose[1]:.3f},{auc_max_loose[2]:.3f}] (vs the whole-chunk 0.72)")
    print("=" * 70)


if __name__ == "__main__":
    main()
