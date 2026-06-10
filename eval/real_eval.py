"""Gercek veri (deepset/prompt-injections) uzerinde GUVENLIK-ONCELIKLI degerlendirme.

  python eval/real_eval.py   (once: python eval/fetch_real.py)

- Veri setinin KENDI train/test ayrimi (rastgele degil, durust).
- Guvenlik-onceligi: esik, train'de recall>=%95 saglayacak sekilde secilir
  (kacirilani minimize et), sonra TEST'te raporlanir.
- Ablation: gercek veride 'artefakt' ozellikler (noktalama/buyukharf) tek basina
  ne yapiyor? (Dusukse gercek veri temiz demektir.)
"""
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np

from eval import metrics
from reasongate import embeddings as emb
from reasongate.features import build_features, FEATURE_NAMES
from reasongate.detectors.ml_injection import REFERENCE_ATTACKS

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "real.json")
TARGET_RECALL = 0.95


def _ml_scores(prompts, ref_mat):
    def norm(M):
        M = np.asarray(M, float)
        return M / (np.linalg.norm(M, axis=1, keepdims=True) + 1e-9)
    q = norm(emb.embed(prompts, input_type="document"))
    return np.clip((q @ ref_mat.T).max(axis=1), 0.0, 1.0)


def tune_threshold(scores, y, target=TARGET_RECALL):
    """recall>=target saglayan EN YUKSEK esik (FPR'yi minimize et)."""
    y = np.asarray(y)
    best = min(scores) - 1e-6
    for th in sorted(set(scores)):
        pred = (np.asarray(scores) >= th).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
        rec = tp / (tp + fn) if (tp + fn) else 0
        if rec >= target:
            best = th
    return best


def report_at(name, sc_tr, ytr, sc_te, yte):
    th = tune_threshold(sc_tr, ytr)
    pred = (np.asarray(sc_te) >= th).astype(int)
    m = metrics.report(list(yte), list(pred))
    print(f"\n=== {name}  (esik={th:.3f}, train recall>={int(TARGET_RECALL*100)}%) ===")
    print(metrics.pretty(m))
    return pred


def main():
    with open(DATA, encoding="utf-8") as f:
        d = json.load(f)
    tr, te = d["train"], d["test"]
    p_tr = [t for t, _ in tr]; y_tr = np.array([l for _, l in tr])
    p_te = [t for t, _ in te]; y_te = np.array([l for _, l in te])
    print(f"GERCEK veri — train {len(tr)} / test {len(te)}")

    def norm(M):
        M = np.asarray(M, float); return M / (np.linalg.norm(M, axis=1, keepdims=True) + 1e-9)
    ref_mat = norm(emb.embed(REFERENCE_ATTACKS, input_type="document"))
    print("Embedding + ozellik cikarimi...")
    ml_tr = _ml_scores(p_tr, ref_mat); ml_te = _ml_scores(p_te, ref_mat)
    X_tr = build_features(p_tr, ml_tr); X_te = build_features(p_te, ml_te)
    i_rule = FEATURE_NAMES.index("kural_skoru"); i_ml = FEATURE_NAMES.index("ml_benzerlik")

    print("\n############  GUVENLIK-ONCELIKLI (recall>=95%)  ############")
    report_at("Kural-only", X_tr[:, i_rule], y_tr, X_te[:, i_rule], y_te)
    report_at("ML benzerlik-only", ml_tr, y_tr, ml_te, y_te)

    from sklearn.tree import DecisionTreeClassifier
    from neural_trees import SoftDecisionTree

    skt = DecisionTreeClassifier(max_depth=4, random_state=42).fit(X_tr, y_tr)
    report_at("sklearn DecisionTree (tum ozellik)", skt.predict_proba(X_tr)[:, 1], y_tr,
              skt.predict_proba(X_te)[:, 1], y_te)

    soft = SoftDecisionTree(depth=4, max_epochs=40, learning_rate=0.05, verbose=False).fit(X_tr, y_tr)
    report_at("SoftDecisionTree / neural-trees", soft.predict_proba(X_tr)[:, 1], y_tr,
              soft.predict_proba(X_te)[:, 1], y_te)

    # --- gercek veride artefakt var mi? ---
    print("\n############  ABLATION (gercek veride artefakt kontrolu)  ############")
    cols_art = [FEATURE_NAMES.index("ozel_karakter"), FEATURE_NAMES.index("buyuk_harf")]
    art = DecisionTreeClassifier(max_depth=3, random_state=42).fit(X_tr[:, cols_art], y_tr)
    m = metrics.report(list(y_te), list(art.predict(X_te[:, cols_art])))
    print(f"Sadece ARTEFAKT (noktalama+buyukharf): recall %{100*m['recall']:.0f}, FPR %{100*m['fpr']:.0f}, F1 {m['f1']:.3f}")
    print("  -> dusukse: gercek veri temiz, sayilar yuzeysel ipucundan degil.")


if __name__ == "__main__":
    main()
