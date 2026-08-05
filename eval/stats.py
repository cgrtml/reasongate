"""McNemar test: compares two detector versions on the SAME set.

"Is the new detector statistically significantly different from the old one?"
Paired, same test set -> this is the correct test for that question.
"""
from __future__ import annotations

from typing import Dict, List


def mcnemar(y_true: List[int], pred_a: List[int], pred_b: List[int]) -> Dict[str, float]:
    # per-sample correctness: does the prediction match the truth?
    a_correct = [int(p == t) for p, t in zip(pred_a, y_true)]
    b_correct = [int(p == t) for p, t in zip(pred_b, y_true)]
    n01 = sum(1 for a, b in zip(a_correct, b_correct) if a == 1 and b == 0)  # A right, B wrong
    n10 = sum(1 for a, b in zip(a_correct, b_correct) if a == 0 and b == 1)  # A wrong, B right
    n = n01 + n10
    if n == 0:
        return {"b": n01, "c": n10, "statistic": 0.0, "p_value": 1.0,
                "method": "no discordant pairs"}
    # continuity-corrected chi-square (df=1). Use scipy when available, else approximate.
    stat = (abs(n01 - n10) - 1) ** 2 / n
    try:
        from scipy.stats import chi2
        p = float(chi2.sf(stat, df=1))
        method = "chi-square + continuity (McNemar)"
    except ImportError:
        import math
        # for df=1, p = erfc(sqrt(stat/2))
        p = math.erfc((stat / 2) ** 0.5)
        method = "chi-square + continuity (McNemar, scipy-free approximation)"
    return {"b": n01, "c": n10, "statistic": round(stat, 4), "p_value": round(p, 5), "method": method}
