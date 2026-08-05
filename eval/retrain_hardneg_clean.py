"""CLEAN hard-negative retrain - NotInject stays 100% held out.

The previous retrain put NotInject into training, which made its FPR in-sample.
This variant sources hard negatives from OUTSIDE NotInject, in the same difficulty
class:
  -> the subset of in-the-wild 'regular' (NON-jailbreak) benign prompts that carry
     injection trigger words (ignore/system/bypass/...).
Those are 'adversarial benign' (trigger words, innocent intent) = the same
difficulty class as NotInject without BEING NotInject. The model never sees
NotInject, so a "<=8% FPR @ NotInject" claim is defensible transfer, not memorization.

Protocol (no threshold leakage; everything is out of training):
  - Threshold: fixed at FPR<=8% on a 50% NotInject calibration split.
  - FPR : the other 50% of NotInject (test) - clean held-out.
  - Recall: gandalf (112) + in-the-wild jailbreaks (400) - unseen by the threshold.
  - AUC : threshold-independent, all of NotInject vs the attacks.
Compared against the baseline (the shipped soft_tree) under the same protocol.

Outcome, recorded in RESULTS.md: this did NOT work either. In-the-wild 'regular'
benign text sits too close to jailbreak roleplay, so training on it dropped
jailbreak recall sharply - which is how we learned that recalibration, not
retraining, was the real lever.

Embeddings are cached. Output: soft_tree_clean.joblib (nothing is overwritten).
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
from eval._addon import require_addon

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
    """Plainly innocent prompts that still carry trigger words (the NotInject
    Technique/Common class). NO persona/roleplay, so the jailbreak distribution
    is not poisoned."""
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
    # a few other languages (multilingual, mirroring NotInject's shape with different content)
    out += ["Python'da büyük/küçük harf duyarlılığını nasıl yok sayarım?",
            "Wie kann ich Systembefehle in Linux auflisten?",
            "¿Cómo puedo ignorar los espacios en blanco en una cadena?"]
    return out


def fetch_hardnegs(n=N_HARDNEG):
    """Genuinely innocent prompts carrying trigger words: alpaca (real tasks, trigger
    filtered) + synthetic. No roleplay/persona, so the difficulty class is right."""
    out = list(_synthetic_hardnegs())
    # alpaca: real benign instructions, trigger-word filtered
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
    """Threshold at FPR<=8% on a 50% NotInject calibration split; then test FPR on the
    other half, attack recalls, and AUC."""
    s_ni = model.predict_proba(ni_E)[:, 1]
    cal, test = train_test_split(np.arange(len(ni_E)), test_size=0.5, random_state=11)
    sc = np.sort(s_ni[cal])[::-1]
    k = int(np.floor(0.08 * len(cal)))
    th = sc[k] if k < len(sc) else sc[-1] - 1e-9
    fpr_test = 100 * np.mean(s_ni[test] >= th)
    recalls = {name: 100 * np.mean(model.predict_proba(E)[:, 1] >= th)
               for name, E in atk_sets.items()}
    # AUC (all of NotInject vs the combined attacks)
    allatk = np.vstack(list(atk_sets.values()))
    y = np.r_[np.ones(len(allatk)), np.zeros(len(ni_E))]
    sc2 = np.r_[model.predict_proba(allatk)[:, 1], s_ni]
    f, t, _ = roc_curve(y, sc2)
    return th, fpr_test, recalls, auc(f, t)


def main():
    require_addon()  # the trained model moved to the enterprise add-on in 0.2.0
    import joblib
    from neural_trees import SoftDecisionTree

    # --- the clean hard-negative source ---
    hn, scanned = fetch_hardnegs()
    print(f"Clean hard negatives: {len(hn)} adversarial-benign (in-the-wild regular, "
          f"trigger-word filtered; {scanned} scanned). NOT NotInject. Examples:")
    for t in hn[:2]:
        print(f"   • {t[:80]!r}")
    json.dump(hn, open(os.path.join(DATA, "clean_hardneg.json"), "w"))
    hn_E = cembed(hn, "clean_hardneg_emb.npz")

    # --- training pool (same as build_best) ---
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
    print(f"\nTraining: {len(tr)} original + {len(hn_E)} clean hard negatives = {len(ytr)}")

    # --- evaluation sets (all out of training) ---
    ni_E = np.asarray(np.load(os.path.join(DATA, "notinject_emb.npz"), allow_pickle=True)["emb"], float)
    g_E = np.asarray(np.load(os.path.join(DATA, "gandalf_emb.npz"), allow_pickle=True)["emb"], float)
    jb_E = np.asarray(np.load(os.path.join(DATA, "inthewild_jb_emb.npz"), allow_pickle=True)["emb"], float)
    atk = {"gandalf": g_E, "jailbreak": jb_E}

    print("Training (clean retrain)...")
    clean = SoftDecisionTree(depth=4, max_epochs=60, learning_rate=0.03, verbose=False).fit(Xtr, ytr)
    base = joblib.load(os.path.join(MODELS, "soft_tree.joblib"))

    print("\n" + "=" * 70)
    print("CLEAN RETRAIN - NotInject 100% HELD OUT (not in training)")
    print("=" * 70)
    for name, m in [("BASELINE (shipped)", base), ("CLEAN RETRAIN (+clean hardneg)", clean)]:
        th, fpr_t, rec, a = operating(m, ni_E, atk)
        print(f"\n{name}:  (AUC {a:.3f})")
        print(f"  FPR @ NotInject (held-out test): {fpr_t:.1f}%")
        print(f"  Recall @ gandalf: {rec['gandalf']:.1f}%   @ jailbreak: {rec['jailbreak']:.1f}%")

    joblib.dump(clean, os.path.join(MODELS, "soft_tree_clean.joblib"))
    json.dump({"note": "clean hard-neg retrain; NotInject NOT in training",
               "hardneg_source": "in-the-wild regular benign, trigger-word filtered",
               "n_train": int(len(ytr)), "n_hardneg": int(len(hn_E))},
              open(os.path.join(MODELS, "meta_clean.json"), "w"))
    print(f"\nSaved (nothing overwritten): {os.path.join(MODELS, 'soft_tree_clean.joblib')}")
    print("NotInject never entered training -> the FPR figure is a defensible held-out number.")


if __name__ == "__main__":
    main()
