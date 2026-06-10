"""Bagimsiz public benchmark: over-defense (yanlis-pozitif) olcumu.

NotInject (leolee99/NotInject) — 339 BENIGN prompt, hepsi injection trigger
kelimeleri ("ignore", "system", "bypass"...) iceriyor ama zararsiz. Iyi bir
guard bunlari BLOKLAMAMALI. Herhangi bir blok = over-defense (yanlis pozitif).

Bu, ReasonGate cekirdek katmanini (kural + normalizasyon) BAGIMSIZ bir
public sette test eder — ic test setimizle ilgisi yok. Tamamen offline
(embedding/API gerekmez), cunku sadece "bloklamadi mi" olcuyoruz.

  python eval/public_bench.py        # cached varsa kullan, yoksa cek
  python eval/public_bench.py --refetch
"""
import json
import os
import sys
import time
import urllib.request
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reasongate.shield import Shield

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "notinject.json")
SPLITS = ["NotInject_one", "NotInject_two", "NotInject_three"]
API = "https://datasets-server.huggingface.co/rows"


def fetch():
    rows = []
    for split in SPLITS:
        offset = 0
        while True:
            url = (f"{API}?dataset=leolee99/NotInject&config=default"
                   f"&split={split}&offset={offset}&length=100")
            with urllib.request.urlopen(url, timeout=60) as r:
                d = json.load(r)
            total = d.get("num_rows_total", 0)
            for item in d["rows"]:
                rr = item["row"]
                rows.append({
                    "prompt": rr.get("prompt", ""),
                    "triggers": len(rr.get("word_list", [])),
                    "category": rr.get("category", "?"),
                    "split": split,
                })
            offset += 100
            if offset >= total:
                break
            time.sleep(0.2)
    os.makedirs(os.path.dirname(DATA), exist_ok=True)
    with open(DATA, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False)
    return rows


def load():
    if os.path.exists(DATA) and "--refetch" not in sys.argv:
        return json.load(open(DATA, encoding="utf-8"))
    print("NotInject cekiliyor (leolee99/NotInject)...")
    rows = fetch()
    print(f"  {len(rows)} benign prompt kaydedildi.")
    return rows


def main():
    rows = load()
    shield = Shield()   # cekirdek: InjectionDetector + NormalizationDetector

    by_split = defaultdict(lambda: [0, 0])      # [blok, toplam]
    by_cat = defaultdict(lambda: [0, 0])
    blocked, flagged, total = 0, 0, len(rows)
    examples = []

    for r in rows:
        res = shield.scan_input(r["prompt"])
        is_block = res.action == "block"
        is_flag = res.action == "flag"
        blocked += is_block
        flagged += is_flag
        by_split[r["split"]][1] += 1
        by_cat[r["category"]][1] += 1
        if is_block:
            by_split[r["split"]][0] += 1
            by_cat[r["category"]][0] += 1
            if len(examples) < 8:
                examples.append((r["prompt"][:70], res.detections))

    print("=" * 64)
    print("NotInject — OVER-DEFENSE (yanlis-pozitif) BENCHMARK")
    print(f"339 benign prompt, hepsi injection trigger kelimeli (bagimsiz public set)")
    print("=" * 64)
    fpr = 100 * blocked / total
    print(f"\nGENEL: blok {blocked}/{total} = %{fpr:.1f} yanlis-pozitif"
          f"  (+ {flagged} flag = %{100*flagged/total:.1f})")
    print(f"Dogru-gecirme (benign accuracy): %{100*(total-blocked)/total:.1f}")

    print("\n--- Trigger sayisina gore (zorluk artar) ---")
    for s in SPLITS:
        b, t = by_split[s]
        print(f"  {s:18}: blok %{100*b/t:.1f}  ({b}/{t})")

    print("\n--- Kategoriye gore (Multilingual = dil kapsami testi) ---")
    for cat, (b, t) in sorted(by_cat.items()):
        print(f"  {cat:22}: blok %{100*b/t:.1f}  ({b}/{t})")

    if examples:
        print("\n--- Yanlis bloklanan ornekler (over-defense) ---")
        for txt, dets in examples[:5]:
            trig = next((d for d in dets if d.triggered), None)
            why = trig.reason if trig else "?"
            print(f"  ✗ \"{txt}\"  -> {why}")

    print("\n--- README/preprint icin markdown ---")
    print("| Guard | NotInject FPR ↓ | Benign accuracy ↑ |")
    print("|---|---:|---:|")
    print(f"| ReasonGate (core, offline) | %{fpr:.1f} | %{100*(total-blocked)/total:.1f} |")


if __name__ == "__main__":
    main()
