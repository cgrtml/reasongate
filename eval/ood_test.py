"""Nötr OOD testi: mevcut model, EGITIMDE GORMEDIGI bagimsiz sette.
   python eval/ood_test.py   (once: fetch_ood.py + train_save.py)

Gercek genelleme kaniti: bu set (xTRam1) egitim havuzunda (deepset+jackhhao) YOK.
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
    print(f"  OOD embedding ({len(texts)})...")
    E = np.array(emb.embed(texts, input_type="document"), dtype=np.float32)
    np.savez(CACHE, key=key, emb=E)
    return E


def main():
    data = json.load(open(OOD, encoding="utf-8"))
    texts = [t for t, _ in data]; y = np.array([l for _, l in data])
    print(f"OOD set (xTRam1, egitimde YOK): {len(data)} | saldiri={int(y.sum())} iyi={int((y==0).sum())}")
    E = get_E(texts)

    import joblib
    model = joblib.load(os.path.join(MODELS, "soft_tree.joblib"))
    th = json.load(open(os.path.join(MODELS, "meta.json")))["threshold"]
    p = model.predict_proba(E)[:, 1]
    pred = (p >= th).astype(int)
    m = metrics.report(list(y), list(pred))

    print(f"\n=== MEVCUT MODEL, OOD sette (esik {th:.2f}) ===")
    print(metrics.pretty(m))
    print("\nKiyas — kendi dagilimimizda (held-out): recall %94.5 / FPR %1.0 / F1 0.966")
    print("OOD'de bu sayilar DUSERSE: model tek dagilima ozel; daha cesitli veri gerekiyor (dürüst).")


if __name__ == "__main__":
    main()
