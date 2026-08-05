"""Hard-negative retrain - the attempted DURABLE cure for ML over-defense.

The ROC diagnosis: thresholding pulls FPR from 23% to 9% but costs 14 points of
recall (AUC 0.928). The cause: the soft tree never saw NotInject-style
'adversarial benign' prompts (trigger words, innocent intent) -> false positives.
The attempted cure: add those hard negatives to training as NEGATIVES and refit.

Hygiene:
  - NotInject is split 60/40: 60% into TRAINING as negatives, 40% HELD OUT for the
    FPR test (the model never sees it).
  - gandalf (112) is NOT in training -> a clean recall test.
  - The original injection held-out split checks that recall is preserved.
Comparison: baseline vs retrained recall at MATCHED FPR (<=8%) - did the curve move up?

All embeddings come from the cache (NO API calls). The model is written to
soft_tree_hardneg.joblib; the shipped model is NOT overwritten (promotion is manual).

Outcome, recorded honestly in RESULTS.md: this retrain was NOT promoted. Training on
NotInject makes NotInject useless as an independent over-defense benchmark, and the
clean finding was that recalibration - not retraining - was the real lever.

  python eval/retrain_hardneg.py
"""
import hashlib
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval._addon import require_addon

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_curve

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
MODELS = os.path.join(os.path.dirname(HERE), "reasongate", "models")


def _emb(name):
    return np.asarray(np.load(os.path.join(DATA, name), allow_pickle=True)["emb"], np.float32)


def recall_at_fpr(scores_pos, scores_neg, target=0.08):
    """Recall on the positives at the threshold where FPR<=target on the negatives."""
    y = np.r_[np.ones(len(scores_pos)), np.zeros(len(scores_neg))]
    s = np.r_[scores_pos, scores_neg]
    fpr, tpr, thr = roc_curve(y, s)
    ok = np.where(fpr <= target)[0]
    i = ok[np.argmax(tpr[ok])]
    from sklearn.metrics import auc
    return 100 * tpr[i], 100 * fpr[i], thr[i], auc(fpr, tpr)


def main():
    require_addon()  # the trained model moved to the enterprise add-on in 0.2.0
    import joblib
    from neural_trees import SoftDecisionTree

    # --- combined training pool (the SAME dedup/order as build_best) ---
    raw = json.load(open(os.path.join(DATA, "pool.json"), encoding="utf-8")) \
        + json.load(open(os.path.join(DATA, "ood.json"), encoding="utf-8"))
    seen, data = set(), []
    for t, l in raw:
        k = " ".join(t.lower().split())
        if k not in seen:
            seen.add(k); data.append([t, int(l)])
    y = np.array([l for _, l in data])
    E = _emb("best_emb_cache.npz")
    assert len(E) == len(data), f"alignment broken: {len(E)} vs {len(data)}"
    idx = np.arange(len(y))
    tr, tmp = train_test_split(idx, test_size=0.4, stratify=y, random_state=42)
    va, te = train_test_split(tmp, test_size=0.5, stratify=y[tmp], random_state=42)

    # --- hard negatives (NotInject) + neutral recall set (gandalf) ---
    ni_E = _emb("notinject_emb.npz")          # 339 benign
    g_E = _emb("gandalf_emb.npz")             # 112 attacks (NOT in training)
    ni_tr, ni_te = train_test_split(np.arange(len(ni_E)), test_size=0.4, random_state=7)
    print(f"NotInject: {len(ni_tr)} training negatives, {len(ni_te)} HELD-OUT FPR test")
    print(f"gandalf: {len(g_E)} recall test (not in training) | injection held-out: {len(te)}")

    # --- training matrices ---
    Xtr = np.vstack([E[tr], ni_E[ni_tr]])
    ytr = np.r_[y[tr], np.zeros(len(ni_tr))]

    print("\nTraining: BASELINE (shipped) vs RETRAINED (+hard negatives)...")
    base = joblib.load(os.path.join(MODELS, "soft_tree.joblib"))   # the shipped model
    retr = SoftDecisionTree(depth=4, max_epochs=60, learning_rate=0.03,
                            verbose=False).fit(Xtr, ytr)

    # --- scores (on the held-out sets) ---
    def proba(m, X): return m.predict_proba(X)[:, 1]
    g_b, g_r = proba(base, g_E), proba(retr, g_E)                  # gandalf (pos)
    ni_b, ni_r = proba(base, ni_E[ni_te]), proba(retr, ni_E[ni_te])  # NotInject held-out (neg)
    te_pos = te[y[te] == 1]
    inj_b, inj_r = proba(base, E[te_pos]), proba(retr, E[te_pos])  # injection recall (pos)
    inj_neg = te[y[te] == 0]
    injn_b, injn_r = proba(base, E[inj_neg]), proba(retr, E[inj_neg])

    print("\n" + "=" * 70)
    print("HARD-NEGATIVE RETRAIN - comparison at matched FPR (held-out)")
    print("=" * 70)
    for name, gs, nis in [("BASELINE (shipped)", g_b, ni_b), ("RETRAINED (+hardneg)", g_r, ni_r)]:
        rec, fpr_, th, a = recall_at_fpr(gs, nis, 0.08)
        print(f"\n{name}:")
        print(f"  @FPR<=8% (held-out NotInject): recall(gandalf) {rec:.1f}%  FPR {fpr_:.1f}%  (AUC {a:.3f})")
    # is injection recall preserved (original held-out test, same threshold logic)
    print("\nIs injection recall preserved (original held-out test):")
    for name, ip, inn in [("BASELINE", inj_b, injn_b), ("RETRAINED", inj_r, injn_r)]:
        rec, fpr_, th, a = recall_at_fpr(ip, inn, 0.08)
        print(f"  {name}: @FPR<=8% recall {rec:.1f}%  (AUC {a:.3f})")

    # --- save (NO overwrite, separate file) ---
    out = os.path.join(MODELS, "soft_tree_hardneg.joblib")
    joblib.dump(retr, out)
    json.dump({"note": "hard-negative retrain (60% of NotInject as training negatives)",
               "datasets": "deepset+jackhhao+xTRam1+NotInject(hardneg)",
               "n_train": int(len(ytr)), "n_hardneg": int(len(ni_tr))},
              open(os.path.join(MODELS, "meta_hardneg.json"), "w"))
    print(f"\nRetrained model saved (the shipped one was NOT overwritten): {out}")
    print("To promote (if it wins): soft_tree_hardneg.joblib -> soft_tree.joblib, then retune thresholds.")


if __name__ == "__main__":
    main()
