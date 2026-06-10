"""Hard-negative retrain — ML over-defense'in KALICI tedavisi.

ROC teshisi: esik FPR'i %23->%9 cekiyor ama 14 puan recall'a mal oluyor
(AUC 0.928). Sebep: soft tree, NotInject-tarzi 'adversarial-benign' promptlari
(trigger-word tasiyan ama masum) hic gormedi -> yanlis pozitif. Tedavi:
bu hard negative'leri training'e NEGATIF olarak ekleyip yeniden egit.

Hijyen:
  - NotInject 60/40 bolunur: %60 EGITIME negatif, %40 HELD-OUT FPR testi (model gormez).
  - gandalf (112) egitimde YOK -> recall testi temiz.
  - Orijinal injection held-out -> recall korunuyor mu kontrol.
Karsilastirma: ESLENMIS FPR'de (<=%8) baseline vs retrained recall (egri yukari ciktimi?).

Tum embedding'ler cache'den (API cagrisi YOK). Model soft_tree_hardneg.joblib'e
yazilir (mevcut model EZILMEZ; iyiyse manuel promote edilir).

  python eval/retrain_hardneg.py
"""
import hashlib
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_curve

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
MODELS = os.path.join(os.path.dirname(HERE), "reasongate", "models")


def _emb(name):
    return np.asarray(np.load(os.path.join(DATA, name), allow_pickle=True)["emb"], np.float32)


def recall_at_fpr(scores_pos, scores_neg, target=0.08):
    """Esik neg'lerde FPR<=target iken pos recall (+kullanilan esik)."""
    y = np.r_[np.ones(len(scores_pos)), np.zeros(len(scores_neg))]
    s = np.r_[scores_pos, scores_neg]
    fpr, tpr, thr = roc_curve(y, s)
    ok = np.where(fpr <= target)[0]
    i = ok[np.argmax(tpr[ok])]
    from sklearn.metrics import auc
    return 100 * tpr[i], 100 * fpr[i], thr[i], auc(fpr, tpr)


def main():
    import joblib
    from neural_trees import SoftDecisionTree

    # --- birlesik egitim havuzu (build_best ile AYNI dedup/sira) ---
    raw = json.load(open(os.path.join(DATA, "pool.json"), encoding="utf-8")) \
        + json.load(open(os.path.join(DATA, "ood.json"), encoding="utf-8"))
    seen, data = set(), []
    for t, l in raw:
        k = " ".join(t.lower().split())
        if k not in seen:
            seen.add(k); data.append([t, int(l)])
    y = np.array([l for _, l in data])
    E = _emb("best_emb_cache.npz")
    assert len(E) == len(data), f"hizalama bozuk: {len(E)} vs {len(data)}"
    idx = np.arange(len(y))
    tr, tmp = train_test_split(idx, test_size=0.4, stratify=y, random_state=42)
    va, te = train_test_split(tmp, test_size=0.5, stratify=y[tmp], random_state=42)

    # --- hard negatives (NotInject) + neutral recall set (gandalf) ---
    ni_E = _emb("notinject_emb.npz")          # 339 benign
    g_E = _emb("gandalf_emb.npz")             # 112 attack (egitimde YOK)
    ni_tr, ni_te = train_test_split(np.arange(len(ni_E)), test_size=0.4, random_state=7)
    print(f"NotInject: {len(ni_tr)} egitim-negatif, {len(ni_te)} HELD-OUT FPR testi")
    print(f"gandalf: {len(g_E)} recall testi (egitimde yok) | injection held-out: {len(te)}")

    # --- egitim matrisleri ---
    Xtr = np.vstack([E[tr], ni_E[ni_tr]])
    ytr = np.r_[y[tr], np.zeros(len(ni_tr))]

    print("\nEgitiliyor: BASELINE (mevcut) vs RETRAINED (+hard negatives)...")
    base = joblib.load(os.path.join(MODELS, "soft_tree.joblib"))   # mevcut model
    retr = SoftDecisionTree(depth=4, max_epochs=60, learning_rate=0.03,
                            verbose=False).fit(Xtr, ytr)

    # --- skorlar (held-out setlerde) ---
    def proba(m, X): return m.predict_proba(X)[:, 1]
    g_b, g_r = proba(base, g_E), proba(retr, g_E)                  # gandalf (pos)
    ni_b, ni_r = proba(base, ni_E[ni_te]), proba(retr, ni_E[ni_te])  # NotInject held-out (neg)
    te_pos = te[y[te] == 1]
    inj_b, inj_r = proba(base, E[te_pos]), proba(retr, E[te_pos])  # injection recall (pos)
    inj_neg = te[y[te] == 0]
    injn_b, injn_r = proba(base, E[inj_neg]), proba(retr, E[inj_neg])

    print("\n" + "=" * 70)
    print("HARD-NEGATIVE RETRAIN — eslenmis FPR'de karsilastirma (held-out)")
    print("=" * 70)
    for name, gs, nis in [("BASELINE (mevcut)", g_b, ni_b), ("RETRAINED (+hardneg)", g_r, ni_r)]:
        rec, fpr_, th, a = recall_at_fpr(gs, nis, 0.08)
        print(f"\n{name}:")
        print(f"  @FPR<=%8 (held-out NotInject): recall(gandalf) %{rec:.1f}  FPR %{fpr_:.1f}  (AUC {a:.3f})")
    # injection recall korunuyor mu (orijinal held-out test, ayni esik mantigi)
    print("\nInjection recall (orijinal held-out test) korunuyor mu:")
    for name, ip, inn in [("BASELINE", inj_b, injn_b), ("RETRAINED", inj_r, injn_r)]:
        rec, fpr_, th, a = recall_at_fpr(ip, inn, 0.08)
        print(f"  {name}: @FPR<=%8 recall %{rec:.1f}  (AUC {a:.3f})")

    # --- kaydet (EZME, ayri dosya) ---
    out = os.path.join(MODELS, "soft_tree_hardneg.joblib")
    joblib.dump(retr, out)
    json.dump({"note": "hard-negative retrain (NotInject %60 train-neg)",
               "datasets": "deepset+jackhhao+xTRam1+NotInject(hardneg)",
               "n_train": int(len(ytr)), "n_hardneg": int(len(ni_tr))},
              open(os.path.join(MODELS, "meta_hardneg.json"), "w"))
    print(f"\nRetrained model kaydedildi (mevcut EZILMEDI): {out}")
    print("Iyiyse promote: soft_tree_hardneg.joblib -> soft_tree.joblib + esikleri yeniden tune et.")


if __name__ == "__main__":
    main()
