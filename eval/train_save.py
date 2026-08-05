"""Trains and saves the shipped model:  python eval/train_save.py

- Splits the real pool into train/val and fits a SoftDecisionTree on embeddings.
- The threshold is chosen on VAL targeting recall>=95% (recall-first).
- Output: reasongate/models/  (model + threshold + attack samples for explanations)

Since 0.2.0 the model directory belongs to the enterprise add-on; this script is
kept here because it documents exactly how the shipped model was produced.
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
import joblib
from reasongate import embeddings as emb

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
POOL = os.path.join(HERE, "data", "pool.json")
CACHE = os.path.join(HERE, "data", "emb_cache.npz")
MODELS = os.path.join(ROOT, "reasongate", "models")
TARGET_RECALL = 0.95


def get_E(texts):
    key = hashlib.md5("||".join(texts).encode()).hexdigest()
    if os.path.exists(CACHE):
        z = np.load(CACHE, allow_pickle=True)
        if str(z["key"]) == key:
            return z["emb"]
    E = np.array(emb.embed(texts, input_type="document"), dtype=np.float32)
    np.savez(CACHE, key=key, emb=E)
    return E


def main():
    require_addon()  # the trained model moved to the enterprise add-on in 0.2.0
    os.makedirs(MODELS, exist_ok=True)
    pool = json.load(open(POOL, encoding="utf-8"))
    texts = [t for t, _ in pool]; y = np.array([l for _, l in pool])
    E = get_E(texts)

    from sklearn.model_selection import train_test_split
    from neural_trees import SoftDecisionTree
    tr, va = train_test_split(np.arange(len(y)), test_size=0.2, stratify=y, random_state=42)

    model = SoftDecisionTree(depth=4, max_epochs=60, learning_rate=0.03, verbose=False)
    model.fit(E[tr], y[tr])

    # recall-first threshold (the highest threshold still giving recall>=95% on VAL)
    pv = model.predict_proba(E[va])[:, 1]; yv = y[va]
    best = float(pv.min()) - 1e-6
    for th in sorted(set(np.round(pv, 4))):
        pred = (pv >= th).astype(int)
        tp = int(((pred == 1) & (yv == 1)).sum()); fn = int(((pred == 0) & (yv == 1)).sum())
        if (tp + fn) and tp / (tp + fn) >= TARGET_RECALL:
            best = float(th)

    # for explanations: attack samples from training (text + embedding), at most 400
    atk_idx = [i for i in tr if y[i] == 1][:400]
    explain = {"texts": [texts[i] for i in atk_idx]}
    np.savez(os.path.join(MODELS, "attack_bank.npz"),
             emb=E[atk_idx], texts=np.array(explain["texts"], dtype=object))

    joblib.dump(model, os.path.join(MODELS, "soft_tree.joblib"))
    json.dump({"threshold": best, "target_recall": TARGET_RECALL, "n_train": len(tr)},
              open(os.path.join(MODELS, "meta.json"), "w"))
    print(f"Saved -> {MODELS}")
    print(f"  threshold={best:.3f} | train={len(tr)} | explanation bank={len(atk_idx)} attacks")

    # reload the saved model and verify it
    m2 = joblib.load(os.path.join(MODELS, "soft_tree.joblib"))
    p = m2.predict_proba(E[va][:3])[:, 1]
    print("  reload OK, sample probabilities:", np.round(p, 3).tolist())


if __name__ == "__main__":
    main()
