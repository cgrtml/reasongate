"""Embedding-as-features siniflandirici (gercek veri, guvenlik-oncelikli).

  python eval/embed_clf.py   (once: python eval/fetch_real.py)

"20 prompta benzerlik" yerine: her prompt'un TAM embedding'i (1024 boyut) ozellik;
546 gercek ornekle siniflandirici egit. Bu, gorevin guclu standart yaklasimi.
"""
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from eval import metrics
from reasongate import embeddings as emb

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "real.json")
TARGET_RECALL = 0.95


def tune_threshold(scores, y, target=TARGET_RECALL):
    y = np.asarray(y); best = float(min(scores)) - 1e-6
    for th in sorted(set(scores)):
        pred = (np.asarray(scores) >= th).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
        if (tp + fn) and tp / (tp + fn) >= target:
            best = th
    return best


def report(name, sc_tr, ytr, sc_te, yte):
    th = tune_threshold(sc_tr, ytr)
    pred = (np.asarray(sc_te) >= th).astype(int)
    m = metrics.report(list(yte), list(pred))
    print(f"\n=== {name}  (esik={th:.3f}) ===")
    print(metrics.pretty(m))


def main():
    with open(DATA, encoding="utf-8") as f:
        d = json.load(f)
    tr, te = d["train"], d["test"]
    ytr = np.array([l for _, l in tr]); yte = np.array([l for _, l in te])
    print(f"GERCEK veri — train {len(tr)} / test {len(te)}")
    print("Embedding (1024 boyut) hesaplaniyor...")
    Xtr = np.array(emb.embed([t for t, _ in tr], input_type="document"))
    Xte = np.array(emb.embed([t for t, _ in te], input_type="document"))

    from sklearn.linear_model import LogisticRegression
    from neural_trees import SoftDecisionTree

    print("\n############  EMBEDDING-AS-FEATURES (gercek veri, recall>=95%)  ############")

    lr = LogisticRegression(max_iter=2000, class_weight="balanced").fit(Xtr, ytr)
    report("Lojistik Regresyon (embedding)", lr.predict_proba(Xtr)[:, 1], ytr,
           lr.predict_proba(Xte)[:, 1], yte)

    soft = SoftDecisionTree(depth=4, max_epochs=60, learning_rate=0.03, verbose=False).fit(Xtr, ytr)
    report("SoftDecisionTree (embedding) / neural-trees", soft.predict_proba(Xtr)[:, 1], ytr,
           soft.predict_proba(Xte)[:, 1], yte)

    print("\nKiyas: onceki zayif sinyal (20-prompt benzerligi) recall %95'te FPR ~%57 idi.")


if __name__ == "__main__":
    main()
