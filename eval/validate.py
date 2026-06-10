"""Kapsamli dogrulama: sonuc GERCEK mi ve TUTUYOR mu?  python eval/validate.py

1) Sizinti/kopya kontrolu
2) Trivial baseline'lar (cogunluk, sadece-uzunluk) — model kestirme mi ogrendi?
3) 5-fold capraz-dogrulama: recall/FPR/F1 ortalama ± std (her bolunmede tutuyor mu)
4) 5x2cv F-testi (neural-trees): soft tree vs LogReg farki saglam mi
5) Somut ornek tahminler (TP / FN / FP)
"""
import hashlib
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from reasongate import embeddings as emb

HERE = os.path.dirname(os.path.abspath(__file__))
POOL = os.path.join(HERE, "data", "pool.json")
CACHE = os.path.join(HERE, "data", "emb_cache.npz")


def get_E(texts):
    key = hashlib.md5("||".join(texts).encode()).hexdigest()
    if os.path.exists(CACHE):
        z = np.load(CACHE, allow_pickle=True)
        if str(z["key"]) == key:
            return z["emb"]
    E = np.array(emb.embed(texts, input_type="document"), dtype=np.float32)
    np.savez(CACHE, key=key, emb=E)
    return E


def rff(y_true, y_pred):
    y_true = np.asarray(y_true); y_pred = np.asarray(y_pred)
    tp = int(((y_pred == 1) & (y_true == 1)).sum()); fn = int(((y_pred == 0) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum()); tn = int(((y_pred == 0) & (y_true == 0)).sum())
    rec = tp / (tp + fn) if tp + fn else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    prec = tp / (tp + fp) if tp + fp else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    return rec, fpr, f1


def main():
    pool = json.load(open(POOL, encoding="utf-8"))
    texts = [t for t, _ in pool]; y = np.array([l for _, l in pool])
    print(f"Havuz: {len(pool)} | saldiri={int(y.sum())} iyi={int((y==0).sum())} | base rate=%{100*max(y.mean(),1-y.mean()):.1f}")

    # 1) sizinti/kopya
    norm = [" ".join(t.lower().split()) for t in texts]
    dups = len(norm) - len(set(norm))
    print(f"\n[1] Kopya metin sayisi: {dups} (0 olmali — dedupe edildi)")

    E = get_E(texts)

    from sklearn.model_selection import StratifiedKFold
    from sklearn.linear_model import LogisticRegression
    from sklearn.dummy import DummyClassifier
    from sklearn.tree import DecisionTreeClassifier
    from neural_trees import SoftDecisionTree

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    # 2) trivial baseline'lar
    print("\n[2] Trivial baseline'lar (5-fold ortalama F1 — DUSUK olmali):")
    length_feat = np.array([[len(t)] for t in texts], dtype=float)
    for name, clf, Xb in [
        ("Cogunluk sinifi", DummyClassifier(strategy="most_frequent"), E),
        ("Sadece-uzunluk agaci", DecisionTreeClassifier(max_depth=3, random_state=42), length_feat),
    ]:
        f1s = []
        for tr, te in skf.split(Xb, y):
            clf.fit(Xb[tr], y[tr]); _, _, f1 = rff(y[te], clf.predict(Xb[te])); f1s.append(f1)
        print(f"   {name:24s}: F1 {np.mean(f1s):.3f}")

    # 3) 5-fold CV: gercek modeller (0.5 esik)
    print("\n[3] 5-fold CV (0.5 esik) — ortalama ± std:")
    for name, mk in [
        ("LogReg (embedding)", lambda: LogisticRegression(max_iter=3000, class_weight="balanced")),
        ("SoftDecisionTree (embedding)", lambda: SoftDecisionTree(depth=4, max_epochs=40, learning_rate=0.03, verbose=False)),
    ]:
        R, Fp, F = [], [], []
        for tr, te in skf.split(E, y):
            m = mk(); m.fit(E[tr], y[tr])
            rec, fpr, f1 = rff(y[te], m.predict(E[te])); R.append(rec); Fp.append(fpr); F.append(f1)
        print(f"   {name:30s}: recall %{100*np.mean(R):.1f}±{100*np.std(R):.1f} | "
              f"FPR %{100*np.mean(Fp):.1f}±{100*np.std(Fp):.1f} | F1 {np.mean(F):.3f}±{np.std(F):.3f}")

    # 4) 5x2cv F-testi
    print("\n[4] 5x2cv F-testi (neural-trees): SoftDecisionTree vs LogReg")
    try:
        from neural_trees.statistical_tests import combined_5x2cv_f_test
        res = combined_5x2cv_f_test(
            SoftDecisionTree(depth=4, max_epochs=25, learning_rate=0.03, verbose=False),
            LogisticRegression(max_iter=2000, class_weight="balanced"),
            E, y, random_state=42)
        print("   " + str(res).replace("\n", "\n   "))
    except Exception as e:
        print("   hata:", e)

    # 5) somut ornekler
    print("\n[5] Somut tahminler (LogReg, son fold):")
    tr, te = list(skf.split(E, y))[0]
    lr = LogisticRegression(max_iter=3000, class_weight="balanced").fit(E[tr], y[tr])
    pred = lr.predict(E[te])
    def show(kind, mask, k=2):
        idxs = np.array(te)[mask][:k]
        for i in idxs:
            print(f"   [{kind}] gercek={y[i]} -> {texts[i][:80]}")
    yte = y[te]
    show("DOGRU-saldiri (TP)", (pred == 1) & (yte == 1))
    show("KACIRILAN (FN)", (pred == 0) & (yte == 1))
    show("YANLIS-ALARM (FP)", (pred == 1) & (yte == 0))


if __name__ == "__main__":
    main()
