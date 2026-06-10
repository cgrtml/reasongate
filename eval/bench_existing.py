"""Kafa-kafaya kiyas: BIZIM model vs mevcut firma modeli (ProtectAI deberta).
  python eval/bench_existing.py

Adil zemin: bizim SoftDecisionTree'nin EGITIMDE GORMEDIGI held-out set (train_save
ile ayni 80/20, seed 42 -> va). Iki modeli ayni ornveklerde olcer.

DURUST UYARI: ProtectAI muhtemelen deepset/jackhhao benzeri veriyle egitildi
(yaygin egitim setleri) -> onun sayilari train-overlap ile sisebilir; bizimki va'da
gercekten held-out. Bunu akilda tut.
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

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
POOL = os.path.join(HERE, "data", "pool.json")
CACHE = os.path.join(HERE, "data", "emb_cache.npz")
MODELS = os.path.join(ROOT, "reasongate", "models")


def main():
    pool = json.load(open(POOL, encoding="utf-8"))
    texts = [t for t, _ in pool]; y = np.array([l for _, l in pool])
    E = np.load(CACHE, allow_pickle=True)["emb"]

    from sklearn.model_selection import train_test_split
    tr, va = train_test_split(np.arange(len(y)), test_size=0.2, stratify=y, random_state=42)
    yva = y[va]
    print(f"Held-out (bizim modelin gormedigi): {len(va)} ornek "
          f"(saldiri={int(yva.sum())}, iyi={int((yva==0).sum())})")

    # --- BIZIM model ---
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

    # ProtectAI'yi BIZIM recall'a esitleyip FPR kiyasi (adil operasyon noktasi)
    our_recall = m_our["recall"]
    th_pa = 0.0
    for t in sorted(set(np.round(pa_p, 4))):
        pred = (pa_p >= t).astype(int)
        tp = int(((pred == 1) & (yva == 1)).sum()); fn = int(((pred == 0) & (yva == 1)).sum())
        if (tp + fn) and tp / (tp + fn) >= our_recall:
            th_pa = t
    m_pa_eq = metrics.report(list(yva), list((pa_p >= th_pa).astype(int)))

    print(f"\n=== BIZIM SoftDecisionTree (esik {th:.2f}, guvenlik-oncelikli) ===")
    print(metrics.pretty(m_our))
    print(f"\n=== ProtectAI deberta @0.5 (varsayilan) ===")
    print(metrics.pretty(m_pa))
    print(f"\n=== ProtectAI, bizim recall'a (%{100*our_recall:.0f}) esitlenince (esik {th_pa:.2f}) ===")
    print(metrics.pretty(m_pa_eq))

    print("\nNOT: ProtectAI deepset/jackhhao benzeri veriyle egitilmis olabilir "
          "(train-overlap -> onun lehine sapma). Bizimki va'da gercekten held-out.")


if __name__ == "__main__":
    main()
