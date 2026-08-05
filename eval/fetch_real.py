"""Fetches the real injection data (deepset/prompt-injections) and saves it locally.

  python eval/fetch_real.py

HuggingFace datasets-server API (stdlib urllib, no extra dependency).
Output: eval/data/real.json  {"train":[[text,label],...], "test":[...]}
The data is gitignored (never committed).
"""
import json
import os
import time
import urllib.request

DATASET = "deepset/prompt-injections"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "real.json")
API = "https://datasets-server.huggingface.co/rows"


def fetch_split(split):
    rows, offset = [], 0
    while True:
        url = f"{API}?dataset={DATASET}&config=default&split={split}&offset={offset}&length=100"
        with urllib.request.urlopen(url, timeout=60) as r:
            d = json.load(r)
        total = d.get("num_rows_total", 0)
        for item in d["rows"]:
            rr = item["row"]
            txt = (rr.get("text") or "").strip()
            if txt:
                rows.append([txt, int(rr.get("label", 0))])
        offset += 100
        if offset >= total:
            break
        time.sleep(0.3)
    return rows


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    data = {}
    for split in ("train", "test"):
        try:
            rows = fetch_split(split)
            data[split] = rows
            n1 = sum(l for _, l in rows)
            print(f"{split}: {len(rows)} samples | injection={n1} benign={len(rows)-n1}")
        except Exception as e:
            print(f"{split}: ERROR {e}")
            data[split] = []
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    print(f"Saved: {OUT}")


if __name__ == "__main__":
    main()
