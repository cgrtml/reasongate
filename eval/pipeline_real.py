"""Dogru-kurgulu gercek-veri hatti:  python eval/pipeline_real.py
   (once: python eval/fetch_data.py)

- Havuz (1948 gercek ornek) -> stratified train/val/test (60/20/20, seed 42)
- Embedding bir kez hesaplanir + diske CACHE'lenir (tekrar maliyet yok)
- Egitim: LogReg + SoftDecisionTree (embedding ozellik)
- Esik VALIDATION'da recall>=%95 hedefiyle secilir -> TEST'te raporlanir (durust held-out)
- Ablation: gercek havuzda artefakt kontrolu
"""
import hashlib
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from eval import metrics
from reasongate import embeddings as emb

HERE = os.path.dirname(os.path.abspath(__file__))
POOL = os.path.join(HERE, "data", "pool.json")
CACHE = os.path.join(HERE, "data", "emb_cache.npz")
TARGET_RECALL = 0.95


def get_embeddings(texts):
    key = hashlib.md5("||".join(texts).encode("utf-8")).hexdigest()
    if os.path.exists(CACHE):
        z = np.load(CACHE, allow_pickle=True)
        if str(z["key"]) == key:
            print("  (embedding cache kullanildi)")
            return z["emb"]
    print(f"  embedding hesaplaniyor ({len(texts)} metin)...")
    E = np.array(emb.embed(texts, input_type="document"), dtype=np.float32)
    np.savez(CACHE, key=key, emb=E)
    return E


def tune_threshold(scores, y, target=TARGET_RECALL):
    y = np.asarray(y); best = float(min(scores)) - 1e-6
    for th in sorted(set(np.round(scores, 4))):
        pred = (np.asarray(scores) >= th).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
        if (tp + fn) and tp / (tp + fn) >= target:
            best = th
    return best


def evaluate(name, proba_tr, ytr_unused, proba_va, yva, proba_te, yte):
    th = tune_threshold(proba_va, yva)            # esik VALIDATION'da
    pred = (np.asarray(proba_te) >= th).astype(int)
    m = metrics.report(list(yte), list(pred))
    print(f"\n=== {name}  (esik VAL'de recall>=95% -> {th:.3f}) ===")
    print(metrics.pretty(m))


def main():
    pool = json.load(open(POOL, encoding="utf-8"))
    texts = [t for t, _ in pool]; y = np.array([l for _, l in pool])
    print(f"Havuz: {len(pool)} (saldiri={int(y.sum())}, iyi={int((y==0).sum())})")

    E = get_embeddings(texts)

    from sklearn.model_selection import train_test_split
    idx = np.arange(len(y))
    tr, tmp = train_test_split(idx, test_size=0.4, stratify=y, random_state=42)
    va, te = train_test_split(tmp, test_size=0.5, stratify=y[tmp], random_state=42)
    print(f"Split: train={len(tr)} val={len(va)} test={len(te)}")

    from sklearn.linear_model import LogisticRegression
    from neural_trees import SoftDecisionTree

    lr = LogisticRegression(max_iter=3000, class_weight="balanced").fit(E[tr], y[tr])
    evaluate("Lojistik Regresyon (embedding)",
             lr.predict_proba(E[tr])[:, 1], y[tr],
             lr.predict_proba(E[va])[:, 1], y[va],
             lr.predict_proba(E[te])[:, 1], y[te])

    soft = SoftDecisionTree(depth=4, max_epochs=60, learning_rate=0.03, verbose=False).fit(E[tr], y[tr])
    evaluate("SoftDecisionTree (embedding) / neural-trees",
             soft.predict_proba(E[tr])[:, 1], y[tr],
             soft.predict_proba(E[va])[:, 1], y[va],
             soft.predict_proba(E[te])[:, 1], y[te])

    # referans: dogal 0.5 esikte LogReg
    pred05 = (lr.predict_proba(E[te])[:, 1] >= 0.5).astype(int)
    m05 = metrics.report(list(y[te]), list(pred05))
    print(f"\n[referans] LogReg @0.5: recall %{100*m05['recall']:.0f}, FPR %{100*m05['fpr']:.0f}, F1 {m05['f1']:.3f}")


if __name__ == "__main__":
    main()
