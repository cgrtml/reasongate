"""Neutral OOD test: the shipped model on an independent set it NEVER SAW in training.
   python eval/ood_test.py   (first: fetch_ood.py + train_save.py)

Real generalization evidence: this set (xTRam1) is NOT in the training pool
(deepset+jackhhao).
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
from reasongate import embeddings as emb

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OOD = os.path.join(HERE, "data", "ood.json")
CACHE = os.path.join(HERE, "data", "ood_emb_cache.npz")
MODELS = os.path.join(ROOT, "reasongate", "models")


def get_E(texts):
    key = hashlib.md5("||".join(texts).encode()).hexdigest()
    if os.path.exists(CACHE):
        z = np.load(CACHE, allow_pickle=True)
        if str(z["key"]) == key:
            print("  (OOD embedding cache)")
            return z["emb"]
    print(f"  embedding OOD set ({len(texts)})...")
    E = np.array(emb.embed(texts, input_type="document"), dtype=np.float32)
    np.savez(CACHE, key=key, emb=E)
    return E


def main():
    require_addon()  # the trained model moved to the enterprise add-on in 0.2.0
    data = json.load(open(OOD, encoding="utf-8"))
    texts = [t for t, _ in data]; y = np.array([l for _, l in data])
    print(f"OOD set (xTRam1, NOT in training): {len(data)} | attacks={int(y.sum())} benign={int((y==0).sum())}")
    E = get_E(texts)

    import joblib
    model = joblib.load(os.path.join(MODELS, "soft_tree.joblib"))
    th = json.load(open(os.path.join(MODELS, "meta.json")))["threshold"]
    p = model.predict_proba(E)[:, 1]
    pred = (p >= th).astype(int)
    m = metrics.report(list(y), list(pred))

    print(f"\n=== SHIPPED MODEL on the OOD set (threshold {th:.2f}) ===")
    print(metrics.pretty(m))
    print("\nFor comparison - on our own distribution (held-out): recall 94.5% / FPR 1.0% / F1 0.966")
    print("If these numbers DROP out of distribution: the model is distribution-specific and\n"
          "more diverse data is needed. Reporting that honestly is the point of this script.")


if __name__ == "__main__":
    main()
