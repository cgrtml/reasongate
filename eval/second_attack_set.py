"""A second attack set - reviewer-proof recall (INDEPENDENT of gandalf, semantic).

gandalf is "ignore"-themed; a recall claim resting on it alone invites the charge
of being keyword-favored. This set is TrustAIRLab/in-the-wild-jailbreak-prompts
(real forum jailbreaks - persona/roleplay/persuasion, which never say "ignore
previous instructions").

Clean protocol (no threshold leakage):
  - The threshold is fixed at FPR<=8% on HELD-OUT NotInject (136 rows kept out of
    the retrain).
  - Recall is then measured on this new jailbreak set, which the threshold NEVER saw.
  - Both the BASELINE and the RETRAINED model, with identical threshold logic.

Embeddings are cached (long prompts are truncated to 2000 chars).
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
from eval._addon import require_addon

import numpy as np
from sklearn.model_selection import train_test_split

from reasongate.shield import Shield
from reasongate import embeddings

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
MODELS = os.path.join(os.path.dirname(HERE), "reasongate", "models")
N = 400          # jailbreak sample size
MAXLEN = 2000    # truncation for embedding


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
    print(f"  embedding ({len(texts)} jailbreaks, long -> ~{len(texts)//64+1} calls)...")
    e = np.asarray(embeddings.embed(texts, input_type="document"), float)
    np.savez(p, emb=e, key=key)
    return e


def main():
    require_addon()  # the trained model moved to the enterprise add-on in 0.2.0
    import joblib
    jb = fetch_jailbreaks()
    print(f"Second set: {len(jb)} in-the-wild jailbreaks (semantic). Examples:")
    for t in jb[:2]:
        print(f"   • {t[:85]!r}")
    json.dump(jb, open(os.path.join(DATA, "inthewild_jb.json"), "w"))

    jb_E = cembed(jb, "inthewild_jb_emb.npz")
    g_E = np.asarray(np.load(os.path.join(DATA, "gandalf_emb.npz"), allow_pickle=True)["emb"], float)
    ni_E = np.asarray(np.load(os.path.join(DATA, "notinject_emb.npz"), allow_pickle=True)["emb"], float)
    # the SAME held-out NotInject as the retrain (the 136 rows kept out of training)
    _, ni_te = train_test_split(np.arange(len(ni_E)), test_size=0.4, random_state=7)
    niH = ni_E[ni_te]

    sh = Shield()
    core_jb = 100 * np.mean([sh.scan_input(t).action == "block" for t in jb])

    def thr_at_fpr(model, target=0.08):
        s = model.predict_proba(niH)[:, 1]
        s_sorted = np.sort(s)[::-1]
        k = int(np.floor(target * len(s)))   # the number of false positives allowed
        return s_sorted[k] if k < len(s) else s_sorted[-1] - 1e-9

    print(f"\nCore (offline) recall @ in-the-wild jailbreaks: {core_jb:.1f}%"
          f"  (low = the set is NOT keyword-favored, it is semantic)")
    print("\n" + "=" * 64)
    print("REVIEWER-PROOF RECALL - threshold fixed at FPR<=8% on held-out NotInject")
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
    print("Note: the threshold is fixed at FPR<=8% on 136 held-out benign rows; recall is")
    print("measured on two INDEPENDENT attack sets the threshold never saw.")
    print("gandalf = keyword-themed, in-the-wild jailbreaks = semantic.")


if __name__ == "__main__":
    main()
