"""ROC/PR + honest threshold recalibration (the ML over-defense diagnosis).

The problem: at the recall-first threshold (0.8395) the ML detector gives 23% FPR
on NotInject - it punctures the low-over-defense wedge from the inside. This script:

  1) the FULL ROC/PR curve over the soft-tree scores (the paper figure),
  2) operating points at FPR targets (how much recall is sacrificed),
  3) HONEST threshold selection: choose on a calibration half, report on the
     HELD-OUT half (choosing and reporting on the same set = overfitting the
     benchmark),
  4) Diagnosis: is this only a threshold problem (a good knee) or is a retrain needed.

Data: gandalf (attack=1) + NotInject (benign=0), from the embedding cache (no API).
  python eval/recalibrate.py
Output: the operating-point table + the figure _notes/roc_reasongate.png
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval._addon import require_addon

import numpy as np

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc, precision_recall_curve, average_precision_score
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
MODELS = os.path.join(os.path.dirname(HERE), "reasongate", "models")
FIG = os.path.join(os.path.dirname(HERE), "_notes", "roc_reasongate.png")


def _load_emb(name):
    return np.asarray(np.load(os.path.join(DATA, name), allow_pickle=True)["emb"], float)


def main():
    require_addon()  # the trained model moved to the enterprise add-on in 0.2.0
    import joblib
    model = joblib.load(os.path.join(MODELS, "soft_tree.joblib"))
    cur_th = float(json.load(open(os.path.join(MODELS, "meta.json")))["threshold"])

    atk = _load_emb("gandalf_emb.npz")        # label 1
    ben = _load_emb("notinject_emb.npz")      # label 0
    X = np.vstack([atk, ben])
    y = np.r_[np.ones(len(atk)), np.zeros(len(ben))]
    scores = model.predict_proba(X)[:, 1]

    fpr, tpr, thr = roc_curve(y, scores)
    roc_auc = auc(fpr, tpr)
    prec, rec, _ = precision_recall_curve(y, scores)
    ap = average_precision_score(y, scores)

    def at_threshold(t):
        pred = scores >= t
        r = 100 * np.mean(pred[y == 1])
        f = 100 * np.mean(pred[y == 0])
        return r, f

    def thr_for_fpr(target):
        """Without a calibration split: the threshold maximizing recall at FPR<=target."""
        ok = np.where(fpr <= target)[0]
        i = ok[np.argmax(tpr[ok])]
        return thr[i], 100 * tpr[i], 100 * fpr[i]

    print("=" * 66)
    print("ROC / PR DIAGNOSIS - soft-tree scores (gandalf attacks + NotInject benign)")
    print("=" * 66)
    print(f"ROC-AUC = {roc_auc:.3f}   |   PR-AUC (AP) = {ap:.3f}   "
          f"(pos={int(y.sum())}, neg={int((y==0).sum())})")

    print("\n--- Operating points (whole set, descriptive) ---")
    r0, f0 = at_threshold(cur_th)
    print(f"  Current threshold {cur_th:.3f} (recall-first): recall {r0:.1f}%  FPR {f0:.1f}%")
    for tgt in (0.05, 0.08, 0.10):
        t, r, f = thr_for_fpr(tgt)
        print(f"  target FPR<={int(tgt*100):<2}% -> threshold {t:.3f}: recall {r:.1f}%  FPR {f:.1f}%")
    # knee: max Youden J
    j = tpr - fpr
    ij = int(np.argmax(j))
    print(f"  Knee (max Youden J) threshold {thr[ij]:.3f}: recall {100*tpr[ij]:.1f}%  FPR {100*fpr[ij]:.1f}%")

    # --- HONEST selection: calibration/test split ---
    print("\n--- Honest recalibration (choose on calibration, report on HELD-OUT) ---")
    idx = np.arange(len(y))
    cal, test = train_test_split(idx, test_size=0.5, stratify=y, random_state=42)
    fpr_c, tpr_c, thr_c = roc_curve(y[cal], scores[cal])
    TARGET = 0.08
    ok = np.where(fpr_c <= TARGET)[0]
    chosen = thr_c[ok[np.argmax(tpr_c[ok])]]
    pred_t = scores[test] >= chosen
    r_test = 100 * np.mean(pred_t[y[test] == 1])
    f_test = 100 * np.mean(pred_t[y[test] == 0])
    print(f"  Threshold chosen on calibration for FPR<=8%: {chosen:.3f}")
    print(f"  HELD-OUT test: recall {r_test:.1f}%  FPR {f_test:.1f}%  "
          f"(same test at the shipped 0.84 threshold: recall {at_threshold(cur_th)[0]:.1f}% FPR {at_threshold(cur_th)[1]:.1f}%)")

    # --- diagnosis ---
    _, f_at_knee = at_threshold(thr[ij])
    print("\n--- DIAGNOSIS ---")
    if f_test <= 10:
        print(f"  The threshold alone brings FPR to {f_test:.1f}% -> partly a threshold problem.")
    print(f"  But even at the knee FPR is {100*fpr[ij]:.1f}%; ROC-AUC {roc_auc:.3f}. "
          f"If AUC<0.97, a hard-negative RETRAIN is needed for a durable fix "
          f"(the model never saw NotInject-style adversarial benign text).")

    # --- figure ---
    fig, ax = plt.subplots(1, 2, figsize=(11, 4.5))
    ax[0].plot(fpr, tpr, lw=2, label=f"ReasonGate ML (AUC={roc_auc:.3f})")
    ax[0].plot([0, 1], [0, 1], "--", c="gray", lw=1)
    ax[0].scatter([f0/100], [r0/100], c="red", zorder=5, label=f"current τ={cur_th:.2f}")
    ax[0].scatter([fpr[ij]], [tpr[ij]], c="green", zorder=5, label="knee")
    ax[0].set_xlabel("False-positive rate (NotInject)"); ax[0].set_ylabel("Recall (gandalf)")
    ax[0].set_title("ROC"); ax[0].legend(loc="lower right"); ax[0].grid(alpha=.3)
    ax[1].plot(rec, prec, lw=2, label=f"AP={ap:.3f}")
    ax[1].set_xlabel("Recall"); ax[1].set_ylabel("Precision")
    ax[1].set_title("Precision–Recall"); ax[1].legend(loc="lower left"); ax[1].grid(alpha=.3)
    fig.suptitle("ReasonGate ML detector — operating characteristic", fontweight="bold")
    fig.tight_layout()
    fig.savefig(FIG, dpi=130)
    print(f"\nFigure saved: {FIG}")


if __name__ == "__main__":
    main()
