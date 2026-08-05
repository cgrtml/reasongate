"""Fetches several REAL injection/jailbreak sets, normalizes, dedupes, saves the pool.

  python eval/fetch_data.py

Sources (HF datasets-server, stdlib urllib):
  - deepset/prompt-injections           (text, label)
  - jackhhao/jailbreak-classification   (prompt, type: jailbreak/benign)
  - xTRam1/safe-guard-prompt-injection  (text, label '0'/'1')

Output: eval/data/pool.json  [[text, label], ...]  (label: 1=attack, 0=benign)
The data itself is gitignored.
"""
import json
import os
import time
import urllib.request

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "pool.json")
SRV = "https://datasets-server.huggingface.co"


def _get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)


def fetch_all(ds, text_field, label_field, label_map, cap=None):
    rows = []
    splits = _get(f"{SRV}/splits?dataset={ds}")["splits"]
    for s in splits:
        cfg, sp = s["config"], s["split"]
        offset = 0
        while True:
            d = _get(f"{SRV}/rows?dataset={ds}&config={cfg}&split={sp}&offset={offset}&length=100")
            total = d.get("num_rows_total", 0)
            for it in d["rows"]:
                rr = it["row"]
                txt = (str(rr.get(text_field, "")) or "").strip()
                lab = label_map(rr.get(label_field))
                if txt and lab is not None:
                    rows.append([txt, lab])
            offset += 100
            if offset >= total or (cap and len(rows) >= cap):
                break
            time.sleep(0.25)
        if cap and len(rows) >= cap:
            break
    return rows


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    pool = []
    srcs = [
        ("deepset/prompt-injections", "text", "label", lambda v: int(v) if v is not None else None, None),
        ("jackhhao/jailbreak-classification", "prompt", "type",
         lambda v: 1 if str(v).lower() == "jailbreak" else (0 if str(v).lower() == "benign" else None), None),
        ("xTRam1/safe-guard-prompt-injection", "text", "label",
         lambda v: int(v) if str(v) in ("0", "1") else None, 6000),
    ]
    for ds, tf, lf, lm, cap in srcs:
        try:
            r = fetch_all(ds, tf, lf, lm, cap)
            n1 = sum(l for _, l in r)
            print(f"{ds}: {len(r)} (attacks={n1}, benign={len(r)-n1})")
            pool += r
        except Exception as e:
            print(f"{ds}: ERROR {str(e)[:100]}")

    # dedupe (by text)
    seen, dedup = set(), []
    for t, l in pool:
        k = " ".join(t.lower().split())
        if k not in seen:
            seen.add(k); dedup.append([t, l])
    n1 = sum(l for _, l in dedup)
    print(f"\nPOOL (deduped): {len(dedup)} | attacks={n1} benign={len(dedup)-n1}")
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(dedup, f, ensure_ascii=False)
    print("Saved:", OUT)


if __name__ == "__main__":
    main()
