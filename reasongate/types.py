"""Cekirdek veri tipleri.

Her tespit (Detection) bir GEREKCE tasir — kalkanin "kara kutu degil,
aciklanabilir" olmasinin temeli budur. Her karar (ShieldResult) ayrica
makine-okunur, denetlenebilir bir kayda (to_dict / to_json) cevrilebilir:
benzersiz decision_id, UTC zaman damgasi ve bir sema surumu tasir, boylece
bir SOC/SIEM ya da denetci karari oldugu gibi ingest edebilir.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

# Denetim kaydi sema surumu — kayit formati degisirse artirilir, boylece
# downstream tuketiciler (SIEM, arsiv) hangi surumu okuduklarini bilir.
AUDIT_SCHEMA_VERSION = "1.0"


def _new_decision_id() -> str:
    return uuid.uuid4().hex


def _now_epoch() -> float:
    return datetime.now(timezone.utc).timestamp()


@dataclass
class Detection:
    detector: str            # dedektor adi (orn. "injection")
    triggered: bool          # esik asildi mi
    score: float             # 0..1 risk skoru
    reason: str              # insan-okunur gerekce ("neden")
    matches: List[str] = field(default_factory=list)  # tetikleyen kanitlar

    def to_dict(self) -> dict:
        """Makine-okunur tespit kaydi (denetim/SIEM icin)."""
        return {
            "detector": self.detector,
            "triggered": bool(self.triggered),
            "score": round(float(self.score), 4),
            "reason": self.reason,
            "matches": list(self.matches),
        }


@dataclass
class Segment:
    """Retrieve edilen/arac-uretilen bir icerik parcasi + KOKEN metadata'si.

    Provenance-aware scan_context icin: bir talimatin KULLANICIDAN mi yoksa
    RETRIEVE edilen icerikten mi geldigini metin DEGIL koken belirler
    (bkz. _notes/spec_17_provenance.md). Geriye-uyumlu: scan_context plain
    str de kabul eder; o zaman provenance KAPALIDIR (eski davranis birebir).
    """
    text: str
    source: str = "retrieved"      # "user" | "retrieved" | "tool" | "web" | "file"
    trust: str = "untrusted"       # "trusted" | "untrusted"
    domain: Optional[str] = None   # koken (orn. "wikipedia.org", "inbox", "vendor-x")


@dataclass
class ShieldResult:
    action: str              # "allow" | "flag" | "block"
    stage: str               # "input" | "output" | "context"
    detections: List[Detection]
    output: Optional[str] = None   # blok degilse modelin (taranmis) ciktisi
    # --- Denetim alanlari: her karar benzersiz ve zaman-damgali izlenebilir ---
    decision_id: str = field(default_factory=_new_decision_id)
    timestamp: float = field(default_factory=_now_epoch)  # UTC epoch saniye
    # Bu karari ureten aktif katmanlar (orn. ["injection","normalization"] vs
    # +["ml_injection","provenance"]). Kurumsal eklenti kuruluysa burada gorunur.
    layers: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.action != "block"

    @property
    def risk_score(self) -> float:
        """Karari belirleyen en yuksek tek-dedektor skoru (0 = sinyal yok)."""
        return round(max((d.score for d in self.detections), default=0.0), 4)

    @property
    def triggered_detectors(self) -> List[str]:
        """Esigi asip karara katki yapan dedektorlerin adlari."""
        return [d.detector for d in self.detections if d.triggered]

    def to_dict(self, *, include_output: bool = True) -> dict:
        """Makine-okunur, SIEM-dostu denetim kaydi.

        include_output=False: model ciktisi kayda yazilmaz (hassas icerigin
        denetim hattina sizmasini istemeyen kurumsal kurulumlar icin)."""
        rec = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "decision_id": self.decision_id,
            "timestamp": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
            "stage": self.stage,
            "action": self.action,
            "allowed": self.allowed,
            "risk_score": self.risk_score,
            "layers": self.layers,
            "triggered_detectors": self.triggered_detectors,
            "detections": [d.to_dict() for d in self.detections],
        }
        if include_output:
            rec["output"] = self.output
        return rec

    def to_json(self, *, include_output: bool = True, **json_kwargs) -> str:
        """to_dict'in JSON dizgisi. Turkce gerekceler kacis-edilmez
        (ensure_ascii=False) ki log okunabilir kalsin."""
        json_kwargs.setdefault("ensure_ascii", False)
        return json.dumps(self.to_dict(include_output=include_output), **json_kwargs)

    def explain(self) -> str:
        """Insan-okunur ozet: ne yapildi ve NEDEN."""
        head = {"allow": "ALLOWED", "flag": "FLAGGED", "block": "BLOCKED"}[self.action]
        lines = [f"[{self.stage}] {head}"]
        for d in self.detections:
            mark = "✗" if d.triggered else "·"
            lines.append(f"  {mark} {d.detector} (score={d.score:.2f}): {d.reason}")
            if d.triggered and d.matches:
                lines.append(f"      evidence: {', '.join(d.matches[:5])}")
        return "\n".join(lines)
