"""Kafa-kafaya: ReasonGate vs ProtectAI deberta-v3 — NOTR public setlerde.

Adil zemin: iki taraf da bu setleri egitimde gormedi (varsayim; deberta'nin
egitim seti acik degil — not dusuyoruz). Ayni ornekler, ayni metrikler.

  - Recall  @ Lakera/gandalf (112 atak, notr)
  - FPR     @ NotInject       (339 benign, over-defense ekseni)
  - Latency (prompt basina, CPU)

  python eval/head_to_head.py
"""
import json
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore")
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reasongate.shield import Shield

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
MODELS = os.path.join(os.path.dirname(HERE), "reasongate", "models")


def main():
    # --- veriler ---
    attacks = [r for r in json.load(open(os.path.join(DATA, "gandalf_attacks.json")))] \
        if os.path.exists(os.path.join(DATA, "gandalf_attacks.json")) else None
    # gandalf'i ML benchmark cache'inden degil, ham metinden al
    import urllib.request
    if attacks is None:
        attacks, off = [], 0
        while True:
            u = ("https://datasets-server.huggingface.co/rows?dataset=Lakera/"
                 f"gandalf_ignore_instructions&config=default&split=test&offset={off}&length=100")
            d = json.load(urllib.request.urlopen(u, timeout=40))
            attacks += [it["row"]["text"] for it in d["rows"]]
            off += 100
            if off >= d.get("num_rows_total", 0):
                break
        json.dump(attacks, open(os.path.join(DATA, "gandalf_attacks.json"), "w"))
    benign = [r["prompt"] for r in json.load(open(os.path.join(DATA, "notinject.json")))]

    print(f"Veri: {len(attacks)} atak (gandalf) + {len(benign)} benign (NotInject)\n")

    rows = []  # (isim, recall, fpr, ms/prompt)

    # --- ReasonGate core (offline) ---
    sh = Shield()
    t0 = time.time()
    r = np.mean([sh.scan_input(t).action == "block" for t in attacks]) * 100
    f = np.mean([sh.scan_input(t).action == "block" for t in benign]) * 100
    ms = 1000 * (time.time() - t0) / (len(attacks) + len(benign))
    rows.append(("ReasonGate core (offline)", r, f, ms))

    # --- ReasonGate + ML (cache'li embedding) ---
    try:
        import joblib, hashlib
        from reasongate import embeddings
        model = joblib.load(os.path.join(MODELS, "soft_tree.joblib"))
        th = float(json.load(open(os.path.join(MODELS, "meta.json")))["threshold"])

        def cembed(texts, name):
            p = os.path.join(DATA, name); key = hashlib.sha1("\n".join(texts).encode()).hexdigest()
            if os.path.exists(p):
                z = np.load(p, allow_pickle=True)
                if str(z.get("key")) == key:
                    return np.asarray(z["emb"], float)
            e = np.asarray(embeddings.embed(texts, input_type="document"), float)
            np.savez(p, emb=e, key=key); return e

        ae = cembed(attacks, "gandalf_emb.npz"); be = cembed(benign, "notinject_emb.npz")
        r2 = np.mean(model.predict_proba(ae)[:, 1] >= th) * 100
        f2 = np.mean(model.predict_proba(be)[:, 1] >= th) * 100
        rows.append(("ReasonGate + ML (VoyageAI→soft tree)", r2, f2, None))
    except Exception as e:
        print(f"[ML atlandi: {e}]")

    # --- ProtectAI deberta-v3 ---
    try:
        from transformers import pipeline
        clf = pipeline("text-classification",
                       model="protectai/deberta-v3-base-prompt-injection-v2",
                       truncation=True, max_length=512)
        def pa_block(t):
            out = clf(t)[0]
            return out["label"].upper().startswith("INJECT")
        t0 = time.time()
        r3 = np.mean([pa_block(t) for t in attacks]) * 100
        f3 = np.mean([pa_block(t) for t in benign]) * 100
        ms3 = 1000 * (time.time() - t0) / (len(attacks) + len(benign))
        rows.append(("ProtectAI deberta-v3", r3, f3, ms3))
    except Exception as e:
        print(f"[ProtectAI atlandi: {e}]")

    # --- tablo ---
    print("=" * 72)
    print(f"{'Guard':38} | {'Recall↑':>8} | {'FPR↓':>7} | {'ms/prompt':>9}")
    print("-" * 72)
    for name, r, f, ms in rows:
        msx = f"{ms:.2f}" if ms is not None else "  (ML)"
        print(f"{name:38} | {r:6.1f}% | {f:5.1f}% | {msx:>9}")
    print("=" * 72)
    print("Recall @ gandalf (notr atak) · FPR @ NotInject (over-defense) · CPU latency")

    print("\n--- markdown ---")
    print("| Guard | Recall @ gandalf | FPR @ NotInject | ms/prompt |")
    print("|---|---:|---:|---:|")
    for name, r, f, ms in rows:
        msx = f"{ms:.2f}" if ms is not None else "—"
        print(f"| {name} | {r:.1f}% | {f:.1f}% | {msx} |")


if __name__ == "__main__":
    main()
