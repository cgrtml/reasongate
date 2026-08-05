"""Head-to-head: OUR model vs an existing vendor model (ProtectAI deberta).
  python eval/bench_existing.py

Fair ground: the held-out set our SoftDecisionTree NEVER SAW in training (the same
80/20 split as train_save, seed 42 -> va). Both models are measured on the same samples.

HONEST CAVEAT: ProtectAI was probably trained on data similar to deepset/jackhhao
(the common training sets), so its numbers may be inflated by train overlap, while
ours is genuinely held out on va. Keep that in mind when reading the table.
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
from eval import metrics

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
POOL = os.path.join(HERE, "data", "pool.json")
CACHE = os.path.join(HERE, "data", "emb_cache.npz")
MODELS = os.path.join(ROOT, "reasongate", "models")


def main():
    require_addon()  # the trained model moved to the enterprise add-on in 0.2.0
    pool = json.load(open(POOL, encoding="utf-8"))
    texts = [t for t, _ in pool]; y = np.array([l for _, l in pool])
    E = np.load(CACHE, allow_pickle=True)["emb"]

    from sklearn.model_selection import train_test_split
    tr, va = train_test_split(np.arange(len(y)), test_size=0.2, stratify=y, random_state=42)
    yva = y[va]
    print(f"Held-out (unseen by our model): {len(va)} samples "
          f"(attacks={int(yva.sum())}, benign={int((yva==0).sum())})")

    # --- OUR model ---
    import joblib
    model = joblib.load(os.path.join(MODELS, "soft_tree.joblib"))
    th = json.load(open(os.path.join(MODELS, "meta.json")))["threshold"]
    our_p = model.predict_proba(E[va])[:, 1]
    our_pred = (our_p >= th).astype(int)
    m_our = metrics.report(list(yva), list(our_pred))

    # --- ProtectAI ---
    from transformers import pipeline
    clf = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection-v2",
                   truncation=True, max_length=512, top_k=None)
    pa_p = []
    for t in [texts[i] for i in va]:
        out = clf(t)[0]  # [{'label':..,'score':..}, {...}]
        d = {o["label"].upper(): o["score"] for o in out}
        pa_p.append(d.get("INJECTION", 1 - d.get("SAFE", 0.5)))
    pa_p = np.array(pa_p)
    pa_pred05 = (pa_p >= 0.5).astype(int)
    m_pa = metrics.report(list(yva), list(pa_pred05))

    # match ProtectAI to OUR recall and compare FPR (a fair operating point)
    our_recall = m_our["recall"]
    th_pa = 0.0
    for t in sorted(set(np.round(pa_p, 4))):
        pred = (pa_p >= t).astype(int)
        tp = int(((pred == 1) & (yva == 1)).sum()); fn = int(((pred == 0) & (yva == 1)).sum())
        if (tp + fn) and tp / (tp + fn) >= our_recall:
            th_pa = t
    m_pa_eq = metrics.report(list(yva), list((pa_p >= th_pa).astype(int)))

    print(f"\n=== OUR SoftDecisionTree (threshold {th:.2f}, recall-first) ===")
    print(metrics.pretty(m_our))
    print(f"\n=== ProtectAI deberta @0.5 (default) ===")
    print(metrics.pretty(m_pa))
    print(f"\n=== ProtectAI matched to our recall ({100*our_recall:.0f}%) (threshold {th_pa:.2f}) ===")
    print(metrics.pretty(m_pa_eq))

    print("\nNOTE: ProtectAI may have been trained on data similar to deepset/jackhhao "
          "(train overlap -> bias in its favour). Ours is genuinely held out on va.")


if __name__ == "__main__":
    main()
