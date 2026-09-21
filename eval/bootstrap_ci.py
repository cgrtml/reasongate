"""Bootstrap confidence intervals for the AgentDojo replay.

Reads the JSON that ``eval/agentdojo_gate.py --json`` writes and reports, per
configuration, a 95% percentile-bootstrap interval for the three headline numbers:

- attack success (ASR), resampling (user task, injection task) pairs;
- utility on clean traffic, resampling user tasks;
- utility under attack, resampling pairs.

Resampling is done over the pooled units across the four suites, which matches how the
pair-weighted rows in RESULTS.md are computed. Offline, standard library only.

    python eval/bootstrap_ci.py eval/data/agentdojo/hand_important.json
    python eval/bootstrap_ci.py run.json --resamples 5000 --seed 1
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from typing import Dict, List, Tuple


def _percentile(sorted_vals: List[float], q: float) -> float:
    if not sorted_vals:
        return float("nan")
    k = (len(sorted_vals) - 1) * q
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def bootstrap_mean(values: List[bool], resamples: int, rng: random.Random) -> Tuple[float, float, float]:
    """Point estimate and 95% percentile interval for the mean of a 0/1 list."""
    n = len(values)
    if n == 0:
        return float("nan"), float("nan"), float("nan")
    point = sum(values) / n
    means = []
    for _ in range(resamples):
        total = 0
        for _ in range(n):
            total += values[rng.randrange(n)]
        means.append(total / n)
    means.sort()
    return point, _percentile(means, 0.025), _percentile(means, 0.975)


def load_configs(path: str) -> Dict[Tuple[str, str, str, str, str], List[dict]]:
    with open(path, encoding="utf-8") as fh:
        results = json.load(fh)
    grouped: Dict[Tuple[str, str, str, str, str], List[dict]] = {}
    for r in results:
        key = (r["mode"], r["scope"], r["trust"], r.get("policies", "hand"),
               r.get("attack", "important_instructions"))
        grouped.setdefault(key, []).append(r)
    return grouped


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("json", help="output of eval/agentdojo_gate.py --json")
    ap.add_argument("--resamples", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    grouped = load_configs(args.json)
    rng = random.Random(args.seed)
    print(f"{args.json}: {args.resamples} resamples, seed {args.seed}, 95% percentile intervals\n")
    print("| Gate | Destinations | Trust map | Policies | Attack | Utility, clean | Utility, under attack | ASR |")
    print("|---|---|---|---|---|---:|---:|---:|")
    for (mode, scope, trust, policies, attack), rows in grouped.items():
        clean = [bool(d["utility"]) for r in rows for d in r["detail_clean"].values()]
        under = [bool(d["utility"]) for r in rows for d in r["detail_pairs"].values()]
        asr = [bool(d["attack_succeeded"]) for r in rows for d in r["detail_pairs"].values()]
        cells = []
        for values in (clean, under, asr):
            p, lo, hi = bootstrap_mean(values, args.resamples, rng)
            cells.append(f"{100*p:.1f}% [{100*lo:.1f}, {100*hi:.1f}]")
        label = {"off": "off", "taint": "taint only", "strict": "strict"}[mode]
        print(f"| {label} | {scope} | {trust} | {policies} | {attack} | " + " | ".join(cells) + " |")
    n_pairs = sum(len(r["detail_pairs"]) for r in next(iter(grouped.values())))
    n_tasks = sum(len(r["detail_clean"]) for r in next(iter(grouped.values())))
    print(f"\nUnits: {n_tasks} user tasks (clean utility), {n_pairs} pairs (ASR, utility under attack).")


if __name__ == "__main__":
    sys.exit(main())
