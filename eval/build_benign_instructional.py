"""Benign-instructional FPR set - the indirect-injection counterpart of NotInject.

Legitimate RAG/document content is FULL of imperatives: recipes ("add the flour"),
manuals ("press the button"), tutorials ("write this function"). None of these are
injection - the imperative is about the content's OWN subject, not aimed at the
assistant's output.

When adding meta-directive patterns to the indirect detector, this set measures the
FPR cost: the patterns must NOT over-block legitimate imperative content, or the
over-defense wedge burns.

Sources (all legitimate, imperative-heavy):
  - corbt/all-recipes (recipe directions)
  - tatsu-lab/alpaca (how-to / step-by-step instruction outputs)

  python eval/build_benign_instructional.py   -> eval/data/benign_instructional.json
"""
import json
import os
import re
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "benign_instructional.json")
MAXLEN = 1500
HOWTO = re.compile(r"^\s*(how (do|to|can)|give .*step|describe how|explain how|"
                   r"write .*(instructions|steps|guide|tutorial)|list .*steps|"
                   r"provide .*(instructions|steps))", re.I)


def fetch_recipes(n=200):
    out, off = [], 0
    while len(out) < n:
        u = ("https://datasets-server.huggingface.co/rows?dataset=corbt/all-recipes"
             f"&config=default&split=train&offset={off}&length=100")
        d = json.load(urllib.request.urlopen(u, timeout=60))
        for it in d["rows"]:
            t = (it["row"].get("input") or "").strip()
            if "Directions" in t or "directions" in t:
                out.append(t[:MAXLEN])
        off += 100
        if off >= d.get("num_rows_total", 0):
            break
    return out[:n]


def fetch_alpaca_howto(n=200):
    """Imperative outputs of how-to instructions (legitimate step-by-step procedures)."""
    out, off, scanned = [], 0, 0
    while len(out) < n and scanned < 6000:
        u = ("https://datasets-server.huggingface.co/rows?dataset=tatsu-lab/alpaca"
             f"&config=default&split=train&offset={off}&length=100")
        d = json.load(urllib.request.urlopen(u, timeout=60))
        for it in d["rows"]:
            ins = (it["row"].get("instruction") or "").strip()
            outp = (it["row"].get("output") or "").strip()
            scanned += 1
            if HOWTO.match(ins) and len(outp) > 60:
                out.append(outp[:MAXLEN])
        off += 100
        if off >= d.get("num_rows_total", 0):
            break
    return out[:n]


def main():
    rec = fetch_recipes()
    alp = fetch_alpaca_howto()
    data = [{"text": t, "src": "recipe"} for t in rec] + \
           [{"text": t, "src": "alpaca_howto"} for t in alp]
    json.dump(data, open(OUT, "w"))
    print(f"Benign-instructional FPR set: {len(rec)} recipes + {len(alp)} how-tos = {len(data)}")
    print("Examples:")
    print("  [recipe]", repr(rec[0][:80]))
    if alp:
        print("  [howto] ", repr(alp[0][:80]))
    print(f"Saved: {OUT}")


if __name__ == "__main__":
    main()
