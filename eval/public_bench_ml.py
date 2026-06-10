"""Public benchmark — ML dedektorunun NOTR (egitimde olmayan) sette recall'u.

Model deepset+jackhhao+xTRam1 ile egitildi. Temiz bir genelleme iddiasi icin
bunlarin DISINDA bir set lazim:

  - Recall: Lakera/gandalf_ignore_instructions (777 gercek adversarial atak —
    Gandalf oyununda insanlarin sifre cikarma denemeleri; yaratici/persuasion-
    tabanli, egitimde YOK). Hepsi saldiri -> recall = bloklanan oran.
  - FPR: leolee99/NotInject (339 benign) -> ML over-block ediyor mu.

Embedding'ler batch + cache (eval/data/) -> tekrar calistirinca API ucreti yok.
Cekirdek (offline) ile ML yan yana raporlanir.

  python eval/public_bench_ml.py
"""
import hashlib
import json
import os
import sys
import time
import urllib.request

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reasongate.shield import Shield
from reasongate import embeddings

DATADIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
MODELS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "reasongate", "models")
API = "https://datasets-server.huggingface.co/rows"


def _fetch(dataset, split, col, limit=None):
    rows, offset = [], 0
    while True:
        url = f"{API}?dataset={dataset}&config=default&split={split}&offset={offset}&length=100"
        with urllib.request.urlopen(url, timeout=60) as r:
            d = json.load(r)
        total = d.get("num_rows_total", 0)
        for item in d["rows"]:
            t = (item["row"].get(col) or "").strip()
            if t:
                rows.append(t)
        offset += 100
        if (limit and len(rows) >= limit) or offset >= total:
            break
        time.sleep(0.2)
    return rows[:limit] if limit else rows


def _cached_embed(texts, cache_name):
    """Batch embed, sonucu cache'le. texts ayni kalirsa API'ye gitme."""
    path = os.path.join(DATADIR, cache_name)
    key = hashlib.sha1("\n".join(texts).encode()).hexdigest()
    if os.path.exists(path):
        z = np.load(path, allow_pickle=True)
        if str(z.get("key")) == key:
            return np.asarray(z["emb"], dtype=float)
    print(f"  embedding ({len(texts)} metin, ~{len(texts)//128 + 1} API cagrisi)...")
    emb = np.asarray(embeddings.embed(texts, input_type="document"), dtype=float)
    np.savez(path, emb=emb, key=key)
    return emb


def main():
    import joblib
    model = joblib.load(os.path.join(MODELS, "soft_tree.joblib"))
    th = float(json.load(open(os.path.join(MODELS, "meta.json")))["threshold"])
    shield = Shield()  # cekirdek (offline)

    print("Lakera/gandalf cekiliyor (notr, egitimde YOK)...")
    attacks = _fetch("Lakera/gandalf_ignore_instructions", "test", "text")
    print(f"  {len(attacks)} adversarial atak. Ornek:")
    for t in attacks[:2]:
        print(f"    • {t[:90]!r}")
    benign = json.load(open(os.path.join(DATADIR, "notinject.json"), encoding="utf-8"))
    benign = [r["prompt"] for r in benign]

    # --- embeddingler (cache) ---
    print("Embedding (cache'li):")
    atk_emb = _cached_embed(attacks, "gandalf_emb.npz")
    ben_emb = _cached_embed(benign, "notinject_emb.npz")

    # --- ML tahmin ---
    atk_p = model.predict_proba(atk_emb)[:, 1]
    ben_p = model.predict_proba(ben_emb)[:, 1]
    ml_recall = 100 * np.mean(atk_p >= th)
    ml_fpr = 100 * np.mean(ben_p >= th)

    # --- Cekirdek (offline) ---
    core_recall = 100 * np.mean([shield.scan_input(t).action == "block" for t in attacks])
    core_fpr = 100 * np.mean([shield.scan_input(t).action == "block" for t in benign])

    print("\n" + "=" * 64)
    print("NOTR PUBLIC SET — GENELLEME (model bu setleri GORMEDI)")
    print("=" * 64)
    print(f"Recall  @ Lakera/gandalf  ({len(attacks)} atak):")
    print(f"  Cekirdek (offline) : %{core_recall:.1f}")
    print(f"  + ML (soft tree)   : %{ml_recall:.1f}")
    print(f"FPR     @ NotInject       ({len(benign)} benign):")
    print(f"  Cekirdek (offline) : %{core_fpr:.1f}")
    print(f"  + ML (soft tree)   : %{ml_fpr:.1f}")

    print("\n--- README/preprint icin markdown ---")
    print("| Katman | Recall @ gandalf (neutral) | FPR @ NotInject |")
    print("|---|---:|---:|")
    print(f"| Core (rule+normalize, offline) | %{core_recall:.1f} | %{core_fpr:.1f} |")
    print(f"| + ML (VoyageAI → soft tree) | %{ml_recall:.1f} | %{ml_fpr:.1f} |")


if __name__ == "__main__":
    main()
