"""Ikinci saldiri seti — reviewer-proof recall (gandalf'tan BAGIMSIZ, semantik).

gandalf "ignore"-temali; recall iddiasi tek ona dayanirsa "keyword-favored" denir.
Bu set: TrustAIRLab/in-the-wild-jailbreak-prompts (gercek forum jailbreak'leri —
persona/roleplay/persuasion, "ignore previous instructions" demiyor).

Temiz protokol (eşik sızıntısı yok):
  - Esik, HELD-OUT NotInject (136, retrain'de egitime girmeyen) uzerinde FPR<=%8'e sabitlenir.
  - Recall, bu yeni jailbreak setinde olculur — esik bu seti HIC gormedi.
  - Hem BASELINE hem RETRAINED model; ayni esik mantigi.

Embedding cache'li (uzun promptlar 2000 char'a kirpilir).
  python eval/second_attack_set.py
"""
import hashlib
import json
import os
import sys
import urllib.request

import warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from sklearn.model_selection import train_test_split

from reasongate.shield import Shield
from reasongate import embeddings

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
MODELS = os.path.join(os.path.dirname(HERE), "reasongate", "models")
N = 400          # jailbreak ornelem boyutu
MAXLEN = 2000    # embedding icin kirpma


def fetch_jailbreaks(n=N):
    ds = "TrustAIRLab/in-the-wild-jailbreak-prompts"
    out, off = [], 0
    while len(out) < n:
        u = (f"https://datasets-server.huggingface.co/rows?dataset={ds}"
             f"&config=jailbreak_2023_12_25&split=train&offset={off}&length=100")
        d = json.load(urllib.request.urlopen(u, timeout=60))
        for it in d["rows"]:
            p = (it["row"].get("prompt") or "").strip()
            if p:
                out.append(p[:MAXLEN])
        off += 100
        if off >= d.get("num_rows_total", 0):
            break
    return out[:n]


def cembed(texts, name):
    p = os.path.join(DATA, name)
    key = hashlib.sha1("\n".join(texts).encode()).hexdigest()
    if os.path.exists(p):
        z = np.load(p, allow_pickle=True)
        if str(z.get("key")) == key:
            return np.asarray(z["emb"], float)
    print(f"  embedding ({len(texts)} jailbreak, uzun -> ~{len(texts)//64+1} cagri)...")
    e = np.asarray(embeddings.embed(texts, input_type="document"), float)
    np.savez(p, emb=e, key=key)
    return e


def main():
    import joblib
    jb = fetch_jailbreaks()
    print(f"Ikinci set: {len(jb)} in-the-wild jailbreak (semantik). Ornek:")
    for t in jb[:2]:
        print(f"   • {t[:85]!r}")
    json.dump(jb, open(os.path.join(DATA, "inthewild_jb.json"), "w"))

    jb_E = cembed(jb, "inthewild_jb_emb.npz")
    g_E = np.asarray(np.load(os.path.join(DATA, "gandalf_emb.npz"), allow_pickle=True)["emb"], float)
    ni_E = np.asarray(np.load(os.path.join(DATA, "notinject_emb.npz"), allow_pickle=True)["emb"], float)
    # retrain ile AYNI held-out NotInject (egitime girmeyen 136)
    _, ni_te = train_test_split(np.arange(len(ni_E)), test_size=0.4, random_state=7)
    niH = ni_E[ni_te]

    sh = Shield()
    core_jb = 100 * np.mean([sh.scan_input(t).action == "block" for t in jb])

    def thr_at_fpr(model, target=0.08):
        s = model.predict_proba(niH)[:, 1]
        s_sorted = np.sort(s)[::-1]
        k = int(np.floor(target * len(s)))   # izin verilen FP sayisi
        return s_sorted[k] if k < len(s) else s_sorted[-1] - 1e-9

    print(f"\nCore (offline) recall @ in-the-wild jailbreaks: %{core_jb:.1f}"
          f"  (dusuk = set keyword-favored DEGIL, semantik)")
    print("\n" + "=" * 64)
    print("REVIEWER-PROOF RECALL — esik held-out NotInject'te FPR<=%8'e sabit")
    print("=" * 64)
    print(f"{'Model':26} | {'recall@jailbreak':>16} | {'recall@gandalf':>14}")
    print("-" * 64)
    for label, fname in [("BASELINE", "soft_tree.joblib"),
                         ("RETRAINED (+hardneg)", "soft_tree_hardneg.joblib")]:
        m = joblib.load(os.path.join(MODELS, fname))
        th = thr_at_fpr(m)
        r_jb = 100 * np.mean(m.predict_proba(jb_E)[:, 1] >= th)
        r_g = 100 * np.mean(m.predict_proba(g_E)[:, 1] >= th)
        print(f"{label:26} | {r_jb:14.1f}% | {r_g:12.1f}%")
    print("=" * 64)
    print("Not: esik 136 held-out benign'de FPR<=%8'e sabit; recall iki BAGIMSIZ")
    print("atak setinde olculur (esik onlari gormedi). gandalf=keyword, jailbreak=semantik.")


if __name__ == "__main__":
    main()
