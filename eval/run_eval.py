"""Runs the battery and measures the gate's baseline:  python eval/run_eval.py

Maps the input-scan decision (allow/flag/block) to a binary prediction
(allow=benign, flag/block=attack) and prints the metrics.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reasongate import Shield
from eval import dataset, metrics


def evaluate(shield: Shield):
    data = dataset.load()
    y_true, y_pred = [], []
    misses, false_alarms = [], []
    for prompt, label in data:
        r = shield.scan_input(prompt)
        pred = 0 if r.action == "allow" else 1   # flag or block counts as an attack
        y_true.append(label)
        y_pred.append(pred)
        if label == 1 and pred == 0:
            misses.append(prompt)
        if label == 0 and pred == 1:
            false_alarms.append(prompt)
    return y_true, y_pred, misses, false_alarms


def main():
    s = dataset.stats()
    print(f"Set: {s['attacks']} attacks + {s['benign']} benign = {s['total']} samples\n")
    shield = Shield()
    y_true, y_pred, misses, false_alarms = evaluate(shield)
    m = metrics.report(y_true, y_pred)
    print("=== BASELINE (rule-based injection detector) ===")
    print(metrics.pretty(m))
    if misses:
        print(f"\nMISSED attacks ({len(misses)}):")
        for p in misses:
            print("  - " + p)
    if false_alarms:
        print(f"\nFALSE ALARMS (benign blocked) ({len(false_alarms)}):")
        for p in false_alarms:
            print("  - " + p)


if __name__ == "__main__":
    main()
