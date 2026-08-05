"""Model comparison:  python eval/train_tree.py

Soft Decision Tree (neural-trees) vs sklearn DecisionTree vs the ML baseline.
Features: rule score + ML similarity + text features.

Rigor: a train/test split (no leakage) plus statistical comparison via
neural-trees' combined_5x2cv_f_test and mcnemar_test. Explainability: the
resulting decision rules are printed.
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
from eval._addon import require_addon
require_addon()  # the ML detector moved to the enterprise add-on in 0.2.0

from reasongate.detectors.ml_injection import REFERENCE_ATTACKS


def _ml_scores(prompts):
    def norm(M):
        M = np.asarray(M, float)
        return M / (np.linalg.norm(M, axis=1, keepdims=True) + 1e-9)
    ref = norm(emb.embed(REFERENCE_ATTACKS, input_type="document"))
    qry = norm(emb.embed(prompts, input_type="document"))
    return np.clip((qry @ ref.T).max(axis=1), 0.0, 1.0).tolist()


def _report(name, y_true, y_pred):
    print(f"\n=== {name} ===")
    print(metrics.pretty(metrics.report(list(y_true), list(y_pred))))


def main():
    data = dataset.load()
    prompts = [p for p, _ in data]
    y = np.array([lbl for _, lbl in data], dtype=int)

    print(f"Embedding + feature extraction ({len(prompts)} prompts)...")
    ml = _ml_scores(prompts)
    X = build_features(prompts, ml)
    ml = np.array(ml)

    from sklearn.model_selection import train_test_split
    from sklearn.tree import DecisionTreeClassifier, export_text
    from neural_trees import SoftDecisionTree
    from neural_trees.statistical_tests import combined_5x2cv_f_test, mcnemar_test

    Xtr, Xte, ytr, yte, mltr, mlte = train_test_split(
        X, y, ml, test_size=0.3, stratify=y, random_state=42)

    # --- models ---
    soft = SoftDecisionTree(depth=3, max_epochs=30, learning_rate=0.05, verbose=False)
    soft.fit(Xtr, ytr)
    pred_soft = np.array(soft.predict(Xte)).astype(int).ravel()

    skt = DecisionTreeClassifier(max_depth=3, random_state=42)
    skt.fit(Xtr, ytr)
    pred_skt = skt.predict(Xte).astype(int)

    pred_ml = (mlte >= 0.60).astype(int)   # the ML baseline (test slice)

    # --- held-out metrics ---
    print("\n################  HELD-OUT TEST METRICS  ################")
    _report("ML-baseline (embedding @0.60)", yte, pred_ml)
    _report("sklearn DecisionTree", yte, pred_skt)
    _report("SoftDecisionTree / neural-trees", yte, pred_soft)

    # --- McNemar: soft vs sklearn (test) ---
    print("\n################  STATISTICAL COMPARISON  ################")
    try:
        mc = mcnemar_test(yte, pred_soft, pred_skt)
        print(f"McNemar (soft vs sklearn, held-out): {mc}")
    except Exception as e:
        print(f"McNemar error: {e}")

    # --- 5x2cv F-test: soft vs sklearn (all data, 10 refits) ---
    try:
        print("\nRunning the 5x2cv F-test (soft vs sklearn, 10 refits - this takes a while)...")
        f = combined_5x2cv_f_test(
            SoftDecisionTree(depth=3, max_epochs=20, learning_rate=0.05, verbose=False),
            DecisionTreeClassifier(max_depth=3, random_state=42),
            X, y, random_state=42)
        print(f"5x2cv F-test result: {f}")
    except Exception as e:
        print(f"5x2cv error: {e}")

    # --- EXPLAINABILITY ---
    print("\n################  EXPLAINABILITY  ################")
    print("\n[sklearn tree - human-readable rules]")
    print(export_text(skt, feature_names=list(FEATURE_NAMES)))
    print("[SoftDecisionTree - feature importance / split weights]")
    try:
        sw = soft.get_split_weights()
        sw = np.abs(np.asarray(sw))
        imp = sw.reshape(-1, len(FEATURE_NAMES)).mean(axis=0) if sw.size % len(FEATURE_NAMES) == 0 else None
        if imp is not None:
            for name, v in sorted(zip(FEATURE_NAMES, imp), key=lambda t: -t[1]):
                print(f"  {name:14s}: {v:.3f}")
        else:
            print("  split-weight shape:", sw.shape)
    except Exception as e:
        print(f"  (soft tree introspection: {e})")


if __name__ == "__main__":
    main()
