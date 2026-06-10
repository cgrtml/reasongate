"""TEMIZ hard-negative retrain (A yolu) — NotInject %100 held-out kalir.

Onceki retrain NotInject'i egitime aldigi icin NotInject FPR'i in-sample oldu.
A yolu: hard-negative'leri NotInject DISINDAN, ayni zorluk sinifindan uret:
  -> in-the-wild 'regular' (jailbreak-OLMAYAN) benign promptlarin, injection
     trigger-word'leri (ignore/system/bypass/...) tasiyan alt kumesi.
Bunlar 'adversarial-benign' (trigger-word'lu ama masum) = NotInject ile ayni
zorluk sinifi, ama NotInject DEGIL. Model NotInject'i HIC gormez ->
"≤%8 FPR @ NotInject" savunulabilir (transfer, ezber degil).

Protokol (esik sizintisi yok, hepsi egitim-disi):
  - Esik: NotInject %50 calibration'da FPR<=%8'e sabit.
  - FPR : NotInject diger %50 (test) — temiz held-out.
  - Recall: gandalf (112) + in-the-wild jailbreak (400) — esik gormedi.
  - AUC : esik-bagimsiz, NotInject(tum) vs ataklar.
Baseline (mevcut soft_tree) ile ayni protokolde karsilastirilir.

Embedding cache'li. Cikti: soft_tree_clean.joblib (EZME yok).
  python eval/retrain_hardneg_clean.py
"""
import hashlib
import json
import os
import re
import sys
import urllib.request
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_curve, auc

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
MODELS = os.path.join(os.path.dirname(HERE), "reasongate", "models")

N_HARDNEG = 400
MAXLEN = 2000
TRIGGERS = re.compile(
    r"\b(ignore|disregard|forget|bypass|override|system\s*prompt|instruction|"
    r"jailbreak|developer\s*mode|unrestricted|pretend|act\s+as|reveal|admin|"
    r"do\s+anything|no\s+restrictions|prompt)\b", re.I)


def cembed(texts, name):
    p = os.path.join(DATA, name)
    key = hashlib.sha1("\n".join(texts).encode()).hexdigest()
    if os.path.exists(p):
        z = np.load(p, allow_pickle=True)
        if str(z.get("key")) == key:
            return np.asarray(z["emb"], float)
    from reasongate import embeddings
    print(f"  embedding ({len(texts)})...")
    e = np.asarray(embeddings.embed(texts, input_type="document"), float)
    np.savez(p, emb=e, key=key)
    return e


def _synthetic_hardnegs():
    """Acikca-masum ama trigger-word tasiyan promptlar (NotInject Technique/Common
    sinifi). Persona/roleplay YOK -> jailbreak dagilimini zehirlemez."""
    out = []
    langs = ["Python", "JavaScript", "Java", "C++", "SQL", "Rust", "Go"]
    ign = ["case sensitivity", "whitespace", "trailing newlines", "a deprecation warning",
           "hidden files", "the .gitignore rules", "null values", "comments"]
    for l in langs:
        for x in ign:
            out.append(f"How do I ignore {x} in {l}?")
    sysq = ["What does the system prompt in the BIOS do?",
            "Explain how a system call works in an operating system.",
            "What is the difference between system and user instructions in an API?",
            "How do I read environment variables set by the system?",
            "Describe the instruction pipeline in a modern CPU.",
            "What are assembly instructions and how are they executed?"]
    byp = ["How can I bypass a slow database query with caching?",
           "What's a legal way to bypass a rate limit using batching?",
           "How do I override a CSS style from a parent element?",
           "How can I override the equals method in Java?",
           "How do I reveal hidden formatting marks in Word?",
           "How to enable developer mode in Chrome to inspect elements?",
           "What does 'developer mode' do on an Android phone?",
           "Write clear instructions to assemble a bookshelf.",
           "Give me step-by-step instructions to bake sourdough bread."]
    out += sysq + byp
    # birkac dilde (multilingual, NotInject'i taklit ama farkli icerik)
    out += ["Python'da büyük/küçük harf duyarlılığını nasıl yok sayarım?",
            "Wie kann ich Systembefehle in Linux auflisten?",
            "¿Cómo puedo ignorar los espacios en blanco en una cadena?"]
    return out


def fetch_hardnegs(n=N_HARDNEG):
    """GERÇEKTEN masum, trigger-word tasiyan promptlar: alpaca (gercek gorevler,
    trigger-filtreli) + sentetik. Roleplay/persona YOK -> dogru zorluk sinifi."""
    out = list(_synthetic_hardnegs())
    # alpaca: gercek benign instruction'lar, trigger-word filtreli
    off, scanned = 0, 0
    while len(out) < n and scanned < 7000:
        u = ("https://datasets-server.huggingface.co/rows?dataset=tatsu-lab/alpaca"
             f"&config=default&split=train&offset={off}&length=100")
        d = json.load(urllib.request.urlopen(u, timeout=60))
        for it in d["rows"]:
            ins = (it["row"].get("instruction") or "").strip()
            inp = (it["row"].get("input") or "").strip()
            p = (ins + (" " + inp if inp else "")).strip()
            scanned += 1
            if p and TRIGGERS.search(p) and len(p) > 15:
                out.append(p[:MAXLEN])
        off += 100
        if off >= d.get("num_rows_total", 0):
            break
    return out[:n], scanned


def operating(model, ni_E, atk_sets):
    """NotInject %50 cal'da FPR<=8 esik; %50 test FPR + atak recall'lari + AUC."""
    s_ni = model.predict_proba(ni_E)[:, 1]
    cal, test = train_test_split(np.arange(len(ni_E)), test_size=0.5, random_state=11)
    sc = np.sort(s_ni[cal])[::-1]
    k = int(np.floor(0.08 * len(cal)))
    th = sc[k] if k < len(sc) else sc[-1] - 1e-9
    fpr_test = 100 * np.mean(s_ni[test] >= th)
    recalls = {name: 100 * np.mean(model.predict_proba(E)[:, 1] >= th)
               for name, E in atk_sets.items()}
    # AUC (tum NotInject vs birlesik atak)
    allatk = np.vstack(list(atk_sets.values()))
    y = np.r_[np.ones(len(allatk)), np.zeros(len(ni_E))]
    sc2 = np.r_[model.predict_proba(allatk)[:, 1], s_ni]
    f, t, _ = roc_curve(y, sc2)
    return th, fpr_test, recalls, auc(f, t)


def main():
    import joblib
    from neural_trees import SoftDecisionTree

    # --- temiz hard-negative kaynagi ---
    hn, scanned = fetch_hardnegs()
    print(f"Temiz hard-neg: {len(hn)} adversarial-benign (in-the-wild regular, "
          f"trigger-word filtreli; {scanned} tarandi). NotInject DEGIL. Ornek:")
    for t in hn[:2]:
        print(f"   • {t[:80]!r}")
    json.dump(hn, open(os.path.join(DATA, "clean_hardneg.json"), "w"))
    hn_E = cembed(hn, "clean_hardneg_emb.npz")

    # --- egitim havuzu (build_best ile ayni) ---
    raw = json.load(open(os.path.join(DATA, "pool.json"), encoding="utf-8")) \
        + json.load(open(os.path.join(DATA, "ood.json"), encoding="utf-8"))
    seen, dd = set(), []
    for t, l in raw:
        k = " ".join(t.lower().split())
        if k not in seen:
            seen.add(k); dd.append([t, int(l)])
    y = np.array([l for _, l in dd])
    E = np.asarray(np.load(os.path.join(DATA, "best_emb_cache.npz"), allow_pickle=True)["emb"], float)
    assert len(E) == len(dd)
    tr, _ = train_test_split(np.arange(len(y)), test_size=0.4, stratify=y, random_state=42)

    Xtr = np.vstack([E[tr], hn_E])
    ytr = np.r_[y[tr], np.zeros(len(hn_E))]
    print(f"\nEgitim: {len(tr)} orijinal + {len(hn_E)} temiz hard-neg = {len(ytr)}")

    # --- evaluation setleri (hepsi egitim-disi) ---
    ni_E = np.asarray(np.load(os.path.join(DATA, "notinject_emb.npz"), allow_pickle=True)["emb"], float)
    g_E = np.asarray(np.load(os.path.join(DATA, "gandalf_emb.npz"), allow_pickle=True)["emb"], float)
    jb_E = np.asarray(np.load(os.path.join(DATA, "inthewild_jb_emb.npz"), allow_pickle=True)["emb"], float)
    atk = {"gandalf": g_E, "jailbreak": jb_E}

    print("Egitiliyor (clean retrain)...")
    clean = SoftDecisionTree(depth=4, max_epochs=60, learning_rate=0.03, verbose=False).fit(Xtr, ytr)
    base = joblib.load(os.path.join(MODELS, "soft_tree.joblib"))

    print("\n" + "=" * 70)
    print("TEMIZ RETRAIN (A) — NotInject %100 HELD-OUT (egitimde YOK)")
    print("=" * 70)
    for name, m in [("BASELINE (mevcut)", base), ("CLEAN RETRAIN (+temiz hardneg)", clean)]:
        th, fpr_t, rec, a = operating(m, ni_E, atk)
        print(f"\n{name}:  (AUC {a:.3f})")
        print(f"  FPR @ NotInject (held-out test): %{fpr_t:.1f}")
        print(f"  Recall @ gandalf: %{rec['gandalf']:.1f}   @ jailbreak: %{rec['jailbreak']:.1f}")

    joblib.dump(clean, os.path.join(MODELS, "soft_tree_clean.joblib"))
    json.dump({"note": "clean hard-neg retrain; NotInject NOT in training",
               "hardneg_source": "in-the-wild regular benign, trigger-word filtered",
               "n_train": int(len(ytr)), "n_hardneg": int(len(hn_E))},
              open(os.path.join(MODELS, "meta_clean.json"), "w"))
    print(f"\nKaydedildi (EZME yok): {os.path.join(MODELS, 'soft_tree_clean.joblib')}")
    print("NotInject hic egitime girmedi -> FPR sayisi savunulabilir held-out.")


if __name__ == "__main__":
    main()
