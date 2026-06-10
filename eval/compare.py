"""Adim 2 karsilastirmasi:  python eval/compare.py

v0 (kural)  vs  ML (embedding)  vs  hibrit (ikisinden biri) — ayni held-out set.
ML icin esik taramasi (recall/FPR dengesi gorunsun) + McNemar (kural vs hibrit).

Veri sizintisi YOK: ML bankasi (REFERENCE_ATTACKS) test setinden ayri ifadeler.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reasongate.detectors.injection import InjectionDetector
from reasongate.detectors.ml_injection import MLInjectionDetector
from eval import dataset, metrics, stats


def main():
    data = dataset.load()
    prompts = [p for p, _ in data]
    y_true = [lbl for _, lbl in data]

    # --- kural skorlari (v0) ---
    rule = InjectionDetector()
    rule_score = [rule.scan(p).score for p in prompts]
    rule_pred = [1 if s >= 0.5 else 0 for s in rule_score]   # v0 baseline mantigi (flag/block)

    # --- ML benzerlik skorlari (TOPLU embed, vektorel) ---
    print(f"Embedding hesaplaniyor ({len(prompts)} prompt + banka, toplu)...")
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

    print("\n=== v0 KURAL (baz cizgisi) ===")
    m_rule = metrics.report(y_true, rule_pred)
    print(metrics.pretty(m_rule))

    print("\n=== ML (embedding) — esik taramasi ===")
    print("  esik |  recall |  FPR  |   F1")
    best = None
    for th in [0.45, 0.50, 0.55, 0.60, 0.65, 0.70]:
        pred = [1 if s >= th else 0 for s in ml_score]
        m = metrics.report(y_true, pred)
        print(f"  {th:.2f} |  %{100*m['recall']:.0f}  | %{100*m['fpr']:.0f} | {m['f1']:.3f}")
        if best is None or m["f1"] > best[1]["f1"]:
            best = (th, m, pred)
    ml_th, m_ml, ml_pred = best
    print(f"  -> en iyi F1 esigi: {ml_th:.2f}")

    # --- hibrit: kural VEYA ml ---
    hybrid_pred = [1 if (r or l) else 0 for r, l in zip(rule_pred, ml_pred)]

    print("\n=== HIBRIT (kural VEYA ML) ===")
    m_hy = metrics.report(y_true, hybrid_pred)
    print(metrics.pretty(m_hy))

    # --- istatistiksel karsilastirma: kural vs hibrit ---
    mc = stats.mcnemar(y_true, rule_pred, hybrid_pred)
    print("\n=== McNemar: v0 kural  vs  hibrit ===")
    print(f"  b(yalniz kural dogru)={mc['b']}  c(yalniz hibrit dogru)={mc['c']}")
    print(f"  istatistik={mc['statistic']}  p-degeri={mc['p_value']}  ({mc['method']})")
    sig = mc["p_value"] < 0.05
    print(f"  -> Fark {'ISTATISTIKSEL OLARAK ANLAMLI' if sig else 'anlamli degil'} (alpha=0.05).")


if __name__ == "__main__":
    main()
