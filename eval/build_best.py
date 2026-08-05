"""A better (more diverse) deployment model:  python eval/build_best.py

Combines 3 real sets (deepset+jackhhao + xTRam1, ~5900), splits train/val/test,
caches embeddings, trains SoftDecisionTree + LogReg, reports held-out numbers and
saves the BEST model for the web demo (reasongate/models/, threshold from VAL at
recall>=95%).

Honest note: this model has now SEEN xTRam1, so the 0.882 OOD figure belongs to
the OLDER model; a genuine OOD number for this one needs a fourth, fresh set.
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
POOL = os.path.join(HERE, "data", "pool.json")
OOD = os.path.join(HERE, "data", "ood.json")
CACHE = os.path.join(HERE, "data", "best_emb_cache.npz")
MODELS = os.path.join(ROOT, "reasongate", "models")
TARGET_RECALL = 0.95


def get_E(texts):
    key = hashlib.md5("||".join(texts).encode()).hexdigest()
    if os.path.exists(CACHE):
        z = np.load(CACHE, allow_pickle=True)
        if str(z["key"]) == key:
            print("  (cache)"); return z["emb"]
    print(f"  embedding ({len(texts)})...")
    E = np.array(emb.embed(texts, input_type="document"), dtype=np.float32)
    np.savez(CACHE, key=key, emb=E)
    return E


def tune(scores, y, target=TARGET_RECALL):
    y = np.asarray(y); best = float(min(scores)) - 1e-6
    for th in sorted(set(np.round(scores, 4))):
        pred = (np.asarray(scores) >= th).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
        if (tp + fn) and tp / (tp + fn) >= target:
            best = float(th)
    return best


def main():
    require_addon()  # the trained model moved to the enterprise add-on in 0.2.0
    raw = json.load(open(POOL, encoding="utf-8")) + json.load(open(OOD, encoding="utf-8"))
    seen, data = set(), []
    for t, l in raw:
        k = " ".join(t.lower().split())
        if k not in seen:
            seen.add(k); data.append([t, int(l)])
    texts = [t for t, _ in data]; y = np.array([l for _, l in data])
    print(f"Combined pool: {len(data)} | attacks={int(y.sum())} benign={int((y==0).sum())}")

    E = get_E(texts)
    from sklearn.model_selection import train_test_split
    from sklearn.linear_model import LogisticRegression
    from neural_trees import SoftDecisionTree

    idx = np.arange(len(y))
    tr, tmp = train_test_split(idx, test_size=0.4, stratify=y, random_state=42)
    va, te = train_test_split(tmp, test_size=0.5, stratify=y[tmp], random_state=42)
    print(f"train={len(tr)} val={len(va)} test={len(te)}")

    soft = SoftDecisionTree(depth=4, max_epochs=60, learning_rate=0.03, verbose=False).fit(E[tr], y[tr])
    lr = LogisticRegression(max_iter=3000, class_weight="balanced").fit(E[tr], y[tr])

    for name, mdl in [("SoftDecisionTree", soft), ("LogReg", lr)]:
        thh = tune(mdl.predict_proba(E[va])[:, 1], y[va])
        pred = (mdl.predict_proba(E[te])[:, 1] >= thh).astype(int)
        m = metrics.report(list(y[te]), list(pred))
        print(f"\n=== {name} (held-out, threshold {thh:.3f}) ===")
        print(metrics.pretty(m))

    # BEST = the soft tree; save it for the web demo
    th_best = tune(soft.predict_proba(E[va])[:, 1], y[va])
    atk = [i for i in tr if y[i] == 1][:400]
    import joblib
    os.makedirs(MODELS, exist_ok=True)
    joblib.dump(soft, os.path.join(MODELS, "soft_tree.joblib"))
    json.dump({"threshold": th_best, "target_recall": TARGET_RECALL,
               "n_train": len(tr), "datasets": "deepset+jackhhao+xTRam1"},
              open(os.path.join(MODELS, "meta.json"), "w"))
    np.savez(os.path.join(MODELS, "attack_bank.npz"),
             emb=E[atk], texts=np.array([texts[i] for i in atk], dtype=object))
    print(f"\nWEB MODEL UPDATED -> {MODELS} (threshold {th_best:.3f}, train {len(tr)})")


if __name__ == "__main__":
    main()
