"""Fetches an independent OOD set (xTRam1/safe-guard-prompt-injection).
   python eval/fetch_ood.py

This set was NOT USED IN TRAINING -> it is the real generalization (OOD) test.
Resilient to HTTP 429.
Output: eval/data/ood.json  [[text, label], ...]   (cap: balanced ~4000)
"""
import json
import os
import time
import urllib.request

DS = "xTRam1/safe-guard-prompt-injection"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ood.json")
SRV = "https://datasets-server.huggingface.co"
CAP_PER_CLASS = 2000


def _get(url, tries=6):
    for i in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429 and i < tries - 1:
                wait = 5 * (i + 1)
                print(f"  429, waiting {wait}s...")
                time.sleep(wait)
            else:
                raise


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    splits = _get(f"{SRV}/splits?dataset={DS}")["splits"]
    pos, neg = [], []
    for s in splits:
        cfg, sp = s["config"], s["split"]
        offset = 0
        while True:
            d = _get(f"{SRV}/rows?dataset={DS}&config={cfg}&split={sp}&offset={offset}&length=100")
            total = d.get("num_rows_total", 0)
            for it in d["rows"]:
                rr = it["row"]
                txt = (str(rr.get("text", "")) or "").strip()
                lab = rr.get("label")
                if not txt or str(lab) not in ("0", "1"):
                    continue
                (pos if str(lab) == "1" else neg).append([txt, int(lab)])
            offset += 100
            if offset >= total or (len(pos) >= CAP_PER_CLASS and len(neg) >= CAP_PER_CLASS):
                break
            time.sleep(0.4)
        if len(pos) >= CAP_PER_CLASS and len(neg) >= CAP_PER_CLASS:
            break

    data = pos[:CAP_PER_CLASS] + neg[:CAP_PER_CLASS]
    # dedupe
    seen, dd = set(), []
    for t, l in data:
        k = " ".join(t.lower().split())
        if k not in seen:
            seen.add(k); dd.append([t, l])
    n1 = sum(l for _, l in dd)
    print(f"OOD set: {len(dd)} | attacks={n1} benign={len(dd)-n1}")
    json.dump(dd, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
    print("Saved:", OUT)


if __name__ == "__main__":
    main()
