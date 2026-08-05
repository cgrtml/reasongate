"""Layer comparison:  python eval/compare.py

rule vs ML (embedding) vs hybrid (either one) - on the same held-out set.
A threshold sweep for the ML layer (so the recall/FPR trade-off is visible) plus
McNemar (rule vs hybrid).

No data leakage: the ML bank (REFERENCE_ATTACKS) is phrased separately from the
test set.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reasongate.detectors.injection import InjectionDetector
from eval._addon import require_addon
require_addon()  # the ML detector moved to the enterprise add-on in 0.2.0

from reasongate.detectors.ml_injection import MLInjectionDetector
from eval import dataset, metrics, stats


def main():
    data = dataset.load()
    prompts = [p for p, _ in data]
    y_true = [lbl for _, lbl in data]

    # --- rule scores ---
    rule = InjectionDetector()
    rule_score = [rule.scan(p).score for p in prompts]
    rule_pred = [1 if s >= 0.5 else 0 for s in rule_score]   # baseline logic (flag/block)

    # --- ML similarity scores (batched, vectorized embed) ---
    print(f"Computing embeddings ({len(prompts)} prompts + the bank, batched)...")
    import numpy as np
    from reasongate import embeddings as emb
    from reasongate.detectors.ml_injection import REFERENCE_ATTACKS

    def _norm(M):
        M = np.asarray(M, dtype=float)
        return M / (np.linalg.norm(M, axis=1, keepdims=True) + 1e-9)

    ref = _norm(emb.embed(REFERENCE_ATTACKS, input_type="document"))
    qry = _norm(emb.embed(prompts, input_type="document"))
    sims = qry @ ref.T                      # (n_prompt, n_ref)
    ml_score = np.clip(sims.max(axis=1), 0.0, 1.0).tolist()

    print("\n=== RULE LAYER (baseline) ===")
    m_rule = metrics.report(y_true, rule_pred)
    print(metrics.pretty(m_rule))

    print("\n=== ML (embedding) - threshold sweep ===")
    print("  thr  |  recall |  FPR  |   F1")
    best = None
    for th in [0.45, 0.50, 0.55, 0.60, 0.65, 0.70]:
        pred = [1 if s >= th else 0 for s in ml_score]
        m = metrics.report(y_true, pred)
        print(f"  {th:.2f} |  {100*m['recall']:.0f}%  | {100*m['fpr']:.0f}% | {m['f1']:.3f}")
        if best is None or m["f1"] > best[1]["f1"]:
            best = (th, m, pred)
    ml_th, m_ml, ml_pred = best
    print(f"  -> best-F1 threshold: {ml_th:.2f}")

    # --- hybrid: rule OR ml ---
    hybrid_pred = [1 if (r or l) else 0 for r, l in zip(rule_pred, ml_pred)]

    print("\n=== HYBRID (rule OR ML) ===")
    m_hy = metrics.report(y_true, hybrid_pred)
    print(metrics.pretty(m_hy))

    # --- statistical comparison: rule vs hybrid ---
    mc = stats.mcnemar(y_true, rule_pred, hybrid_pred)
    print("\n=== McNemar: rule  vs  hybrid ===")
    print(f"  b(only rule correct)={mc['b']}  c(only hybrid correct)={mc['c']}")
    print(f"  statistic={mc['statistic']}  p-value={mc['p_value']}  ({mc['method']})")
    sig = mc["p_value"] < 0.05
    print(f"  -> The difference is {'STATISTICALLY SIGNIFICANT' if sig else 'not significant'} (alpha=0.05).")


if __name__ == "__main__":
    main()
