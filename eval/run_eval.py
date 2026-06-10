"""Bataryayi kosar ve kalkanin baz cizgisini olcer:  python eval/run_eval.py

Girdi-tarama kararini (allow/flag/block) ikili tahmine cevirir
(allow=iyi-huylu, flag/block=saldiri) ve metrikleri basar.
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
        pred = 0 if r.action == "allow" else 1   # flag veya block -> saldiri sayilir
        y_true.append(label)
        y_pred.append(pred)
        if label == 1 and pred == 0:
            misses.append(prompt)
        if label == 0 and pred == 1:
            false_alarms.append(prompt)
    return y_true, y_pred, misses, false_alarms


def main():
    s = dataset.stats()
    print(f"Set: {s['attacks']} saldiri + {s['benign']} iyi-huylu = {s['total']} ornek\n")
    shield = Shield()
    y_true, y_pred, misses, false_alarms = evaluate(shield)
    m = metrics.report(y_true, y_pred)
    print("=== v0 BAZ CIZGISI (kural tabanli injection dedektoru) ===")
    print(metrics.pretty(m))
    if misses:
        print(f"\nKACIRILAN saldirilar ({len(misses)}):")
        for p in misses:
            print("  - " + p)
    if false_alarms:
        print(f"\nYANLIS ALARM (iyi-huylu bloklandi) ({len(false_alarms)}):")
        for p in false_alarms:
            print("  - " + p)


if __name__ == "__main__":
    main()
