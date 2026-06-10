"""Benign-instructional FPR seti — indirect over-defense'in NotInject karsiligi.

Mesru RAG/dokuman icerigi imperatif DOLUDUR: tarifler ("un ekle"), kilavuzlar
("dugmeye bas"), tutorial'lar ("su fonksiyonu yaz"). Bunlar injection DEGIL —
imperatif, icerigin KENDI konusu, asistanin ciktisina yonelik degil.

Indirect dedektorune meta-direktif kalibi eklerken bu set FPR'i olcer: kaliplar
mesru imperatif icerigi over-block ETMEMELI (yoksa wedge geri yanar).

Kaynaklar (hepsi mesru, imperatif-yogun):
  - corbt/all-recipes (tarif yonergeleri)
  - tatsu-lab/alpaca (how-to / adim-adim instruction ciktilari)

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
    """How-to instruction'larin imperatif ciktilari (adim-adim mesru prosedurler)."""
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
    print(f"Benign-instructional FPR seti: {len(rec)} tarif + {len(alp)} how-to = {len(data)}")
    print("Ornekler:")
    print("  [recipe]", repr(rec[0][:80]))
    if alp:
        print("  [howto] ", repr(alp[0][:80]))
    print(f"Kaydedildi: {OUT}")


if __name__ == "__main__":
    main()
