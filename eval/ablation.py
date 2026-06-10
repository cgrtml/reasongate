"""Ablation:  python eval/ablation.py

Soru: yuksek dogruluk GERCEK sinyalden mi, yoksa sentetik veri ARTEFAKTINDAN mi?
Ayni agaci farkli ozellik altkumeleriyle egitip kiyaslar:
  - TUM        : butun ozellikler
  - ANLAMLI    : kural_skoru + ml_benzerlik (gercek injection sinyali)
  - ARTEFAKT   : ozel_karakter + buyuk_harf (supheli yuzeysel ipuclari)

ARTEFAKT tek basina yuksek cikarsa -> yuksek sayilar sahte (veri sizdiriyor).
"""
import os
import sys
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np

from eval import dataset, metrics
from reasongate import embeddings as emb
from reasongate.features import build_features, FEATURE_NAMES
from reasongate.detectors.ml_injection import REFERENCE_ATTACKS


def _ml_scores(prompts):
    def norm(M):
        M = np.asarray(M, float)
        return M / (np.linalg.norm(M, axis=1, keepdims=True) + 1e-9)
    ref = norm(emb.embed(REFERENCE_ATTACKS, input_type="document"))
    qry = norm(emb.embed(prompts, input_type="document"))
    return np.clip((qry @ ref.T).max(axis=1), 0.0, 1.0).tolist()


def main():
    data = dataset.load()
    prompts = [p for p, _ in data]
    y = np.array([l for _, l in data], dtype=int)
    print(f"Embedding + ozellik ({len(prompts)} prompt)...")
    X = build_features(prompts, _ml_scores(prompts))

    from sklearn.model_selection import train_test_split
    from sklearn.tree import DecisionTreeClassifier

    idx = {n: i for i, n in enumerate(FEATURE_NAMES)}
    subsets = {
        "TUM (7 ozellik)":        list(range(len(FEATURE_NAMES))),
        "ANLAMLI (kural+ML)":     [idx["kural_skoru"], idx["ml_benzerlik"]],
        "ARTEFAKT (noktalama+buyukharf)": [idx["ozel_karakter"], idx["buyuk_harf"]],
    }

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
    print(f"\n{'Ozellik kumesi':32s} | recall | FPR  |  F1")
    print("-" * 60)
    for name, cols in subsets.items():
        clf = DecisionTreeClassifier(max_depth=3, random_state=42)
        clf.fit(Xtr[:, cols], ytr)
        pred = clf.predict(Xte[:, cols])
        m = metrics.report(list(yte), list(pred))
        print(f"{name:32s} | %{100*m['recall']:4.0f} | %{100*m['fpr']:3.0f} | {m['f1']:.3f}")

    print("\nYorum: ARTEFAKT tek basina yuksekse -> sayilar yuzeysel ipucundan, GERCEK degil.")


if __name__ == "__main__":
    main()
