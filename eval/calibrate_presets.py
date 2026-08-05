"""Deterministic threshold presets (recall_first / balanced / precision_first).

The threshold is NOT a magic constant picked by eye - it is the output of a
reproducible procedure:

  Each preset is tied to an FPR target. The threshold is the MEDIAN, over 20 seeds
  (0..19), of the smallest tau achieving "FPR <= target" on a 50% NotInject
  calibration split. The reported FPR/recall come from the complementary held-out
  halves.

NotInject is NOT IN TRAINING, so both the threshold selection and the report are
clean. The result is written to meta.json (threshold = the balanced default +
the presets + the derivation rule).

  python eval/calibrate_presets.py
"""
import json
import os
import sys
import statistics as st

import numpy as np
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval._addon import require_addon

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
MODELS = os.path.join(os.path.dirname(HERE), "reasongate", "models")
META = os.path.join(MODELS, "meta.json")
SEEDS = range(20)
PRESETS = {"recall_first": 0.15, "balanced": 0.08, "precision_first": 0.03}


def _emb(n):
    return np.asarray(np.load(os.path.join(DATA, n), allow_pickle=True)["emb"], float)


def main():
    require_addon()  # the trained model moved to the enterprise add-on in 0.2.0
    import joblib
    model = joblib.load(os.path.join(MODELS, "soft_tree.joblib"))
    s_ni = model.predict_proba(_emb("notinject_emb.npz"))[:, 1]
    s_g = model.predict_proba(_emb("gandalf_emb.npz"))[:, 1]
    s_jb = model.predict_proba(_emb("inthewild_jb_emb.npz"))[:, 1]
    n = len(s_ni)

    print("=" * 70)
    print("DETERMINISTIC PRESET CALIBRATION (baseline model, NotInject held out)")
    print(f"threshold = 20-seed median of the smallest tau with FPR<=target (50% NotInject cal)")
    print("=" * 70)
    print(f"{'Preset':16} | {'τ':>6} | {'FPR test':>10} | {'recall gandalf':>14} | {'recall jb':>10}")
    print("-" * 70)

    presets_meta = {}
    for name, target in PRESETS.items():
        taus, fprs, rg, rj = [], [], [], []
        for seed in SEEDS:
            cal, test = train_test_split(np.arange(n), test_size=0.5, random_state=seed)
            sc = np.sort(s_ni[cal])[::-1]
            k = int(np.floor(target * len(cal)))
            tau = float(sc[min(k, len(sc) - 1)])
            taus.append(tau)
            fprs.append(100 * np.mean(s_ni[test] >= tau))
            rg.append(100 * np.mean(s_g >= tau))
            rj.append(100 * np.mean(s_jb >= tau))
        tau_med = float(np.median(taus))
        # reported FPR/recall: at the median threshold over all sets (held-out attacks)
        fpr_at = 100 * np.mean(s_ni >= tau_med)
        presets_meta[name] = {
            "threshold": round(tau_med, 4),
            "target_fpr": target,
            "fpr_test_mean": round(st.mean(fprs), 1),
            "fpr_test_std": round(st.pstdev(fprs), 1),
            "recall_gandalf": round(st.mean(rg), 1),
            "recall_jailbreak": round(st.mean(rj), 1),
        }
        print(f"{name:16} | {tau_med:6.3f} | {st.mean(fprs):4.1f}%+/-{st.pstdev(fprs):<3.1f} "
              f"| {st.mean(rg):5.1f}%+/-{st.pstdev(rg):<3.1f} | {st.mean(rj):5.1f}%+/-{st.pstdev(rj):<3.1f}")

    # --- write meta.json (preserving the existing fields) ---
    meta = json.load(open(META))
    old_th = meta.get("threshold")
    meta["threshold"] = presets_meta["balanced"]["threshold"]   # the default is balanced
    meta["default_preset"] = "balanced"
    meta["presets"] = presets_meta
    meta["calibration"] = ("threshold = median over seeds 0..19 of smallest tau with "
                           "FPR<=target on a random 50% NotInject calibration split; "
                           "reported fpr/recall on complementary held-out halves. "
                           "NotInject is NOT in training.")
    # idempotent: record the originally shipped threshold once, so re-runs do not clobber it
    meta.setdefault("threshold_prev_recall_first_shipped", old_th)
    meta["production_note"] = (
        "Soft-tree scores saturate (bimodal near 0 and 1); all preset thresholds lie in a "
        "~0.03-wide band near 1.0, where ~18% of benign (NotInject) also score >=0.96. "
        "Presets are calibrated operating points, NOT fixed guarantees: monitor the production "
        "score histogram for drift, since a small distribution shift can move FPR "
        "disproportionately (cf. reported FPR sd of ~3.5pts). precision_first (tau~1.0) is the "
        "edge of the slice, not a true high-precision mode. Mitigation: score calibration "
        "(isotonic/Platt) to spread scores before thresholding.")
    json.dump(meta, open(META, "w"), indent=2)
    print("\nmeta.json updated:")
    print(f"  default threshold (balanced): {meta['threshold']} (previously shipped: {old_th})")
    print(f"  presets + derivation rule written.")


if __name__ == "__main__":
    main()
