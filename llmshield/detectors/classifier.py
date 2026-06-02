"""Egitilmis siniflandirici dedektoru (embedding + SoftDecisionTree).

Gercek veride dogrulanmis model (eval/train_save.py ile uretilir). Aciklanabilirlik:
embedding opak oldugu icin gerekce olarak 'en benzer bilinen saldiri' gosterilir.
"""
from __future__ import annotations

import json
import os

import numpy as np

from llmshield.detectors.base import Detector
from llmshield.types import Detection
from llmshield import embeddings

_MODELS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")


class ClassifierDetector(Detector):
    name = "ml_classifier"
    stage = "input"

    def __init__(self, models_dir: str = _MODELS):
        self.dir = models_dir
        self._model = None
        self._th = 0.5
        self._bank_emb = None
        self._bank_txt = None

    def _ensure(self):
        if self._model is not None:
            return
        import joblib
        # once genel 'model.joblib' (deploy/LogReg), yoksa 'soft_tree.joblib' (yerel)
        path = None
        for name in ("model.joblib", "soft_tree.joblib"):
            p = os.path.join(self.dir, name)
            if os.path.exists(p):
                path = p
                break
        if path is None:
            raise RuntimeError("Model yok. Once: python eval/make_deploy_model.py")
        self._model = joblib.load(path)
        meta = json.load(open(os.path.join(self.dir, "meta.json")))
        self._th = float(meta.get("threshold", 0.5))
        bank = np.load(os.path.join(self.dir, "attack_bank.npz"), allow_pickle=True)
        be = np.asarray(bank["emb"], dtype=float)
        self._bank_emb = be / (np.linalg.norm(be, axis=1, keepdims=True) + 1e-9)
        self._bank_txt = list(bank["texts"])

    def scan(self, text: str) -> Detection:
        self._ensure()
        vec = np.asarray(embeddings.embed([text], input_type="document")[0], dtype=float)
        proba = float(self._model.predict_proba(vec.reshape(1, -1))[0, 1])
        triggered = proba >= self._th

        # aciklama: en benzer bilinen saldiri
        v = vec / (np.linalg.norm(vec) + 1e-9)
        sims = self._bank_emb @ v
        i = int(sims.argmax()); sim = float(sims[i])
        nearest = self._bank_txt[i]

        if triggered:
            reason = (f"Siniflandirici saldiri olasiligi {proba:.2f} (esik {self._th:.2f}). "
                      f"En benzer bilinen saldiri (benzerlik {sim:.2f}): \"{nearest[:70]}\"")
        else:
            reason = f"Saldiri olasiligi dusuk ({proba:.2f} < esik {self._th:.2f})."
        return Detection(self.name, triggered, round(proba, 2), reason, [nearest[:70]])
