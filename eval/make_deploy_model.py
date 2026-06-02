"""Hafif deployment modeli (LogReg, torch'suz) uretir + repo'ya koyar.
   python eval/make_deploy_model.py

Sunucuda torch/neural-trees gerekmesin diye soft tree yerine LogReg. app/model/
altina kaydeder (commit edilir; gitignore'daki 'models/' bunu kapsamaz -> 'model' tekil).
"""
import hashlib
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from llmshield import embeddings as emb

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
POOL = os.path.join(HERE, "data", "pool.json")
OOD = os.path.join(HERE, "data", "ood.json")
CACHE = os.path.join(HERE, "data", "best_emb_cache.npz")   # build_best ile ayni anahtar
OUT = os.path.join(ROOT, "app", "model")
TARGET_RECALL = 0.95


def get_E(texts):
    key = hashlib.md5("||".join(texts).encode()).hexdigest()
    if os.path.exists(CACHE):
        z = np.load(CACHE, allow_pickle=True)
        if str(z["key"]) == key:
            print("  (cache)"); return z["emb"]
    print(f"  embedding ({len(texts)})...")
    return np.array(emb.embed(texts, input_type="document"), dtype=np.float32)


def main():
    os.makedirs(OUT, exist_ok=True)
    raw = json.load(open(POOL, encoding="utf-8")) + json.load(open(OOD, encoding="utf-8"))
    seen, data = set(), []
    for t, l in raw:
        k = " ".join(t.lower().split())
        if k not in seen:
            seen.add(k); data.append([t, int(l)])
    texts = [t for t, _ in data]; y = np.array([l for _, l in data])
    E = get_E(texts)

    from sklearn.model_selection import train_test_split
    from sklearn.linear_model import LogisticRegression
    tr, va = train_test_split(np.arange(len(y)), test_size=0.2, stratify=y, random_state=42)

    clf = LogisticRegression(max_iter=3000, class_weight="balanced").fit(E[tr], y[tr])
    pv = clf.predict_proba(E[va])[:, 1]
    th = float(pv.min()) - 1e-6
    for t in sorted(set(np.round(pv, 4))):
        pred = (pv >= t).astype(int)
        tp = int(((pred == 1) & (y[va] == 1)).sum()); fn = int(((pred == 0) & (y[va] == 1)).sum())
        if (tp + fn) and tp / (tp + fn) >= TARGET_RECALL:
            th = float(t)

    import joblib
    joblib.dump(clf, os.path.join(OUT, "model.joblib"))
    json.dump({"threshold": th, "model": "logreg", "n_train": len(tr)},
              open(os.path.join(OUT, "meta.json"), "w"))
    atk = [i for i in tr if y[i] == 1][:400]
    np.savez(os.path.join(OUT, "attack_bank.npz"),
             emb=E[atk], texts=np.array([texts[i] for i in atk], dtype=object))
    size = sum(os.path.getsize(os.path.join(OUT, f)) for f in os.listdir(OUT))
    print(f"Deploy modeli -> {OUT} (esik {th:.3f}, ~{size/1e6:.1f}MB)")


if __name__ == "__main__":
    main()
