"""Girdi normalizasyonu + obfuscation (gizleme) tespiti.

Regex/ML dedektorlerinin EN buyuk acigi: saldirgan metni gizleyince
("1gn0re", sifir-genislik karakterler, Kiril homoglyph'leri, "i g n o r e")
kalip eslesmesi patlar ve saldiri suzulur.

Bu katman saldiri yuzeyini DUZLESTIRIR:
  - Unicode NFKC + homoglyph (Kiril/Yunan -> Latin) katlamasi
  - Gorunmez karakter temizligi (zero-width, bidi, kontrol) — bunlarin
    VARLIGI tek basina guclu bir saldiri sinyalidir
  - Token-kirma ayiraclarini birlestirme ("i.g.n.o.r.e" -> "ignore")
  - Leetspeak katlamasi ("1gn0re" -> "ignore")
  - Gizli base64 yuklerini cozme

Cikti hem TEMIZLENMIS metni hem de UYGULANAN DONUSUMLERI tasir; boylece
karar kara kutu degil, "su gizleme tespit edildi" diye aciklanabilir.
"""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List

from reasongate.detectors.base import Detector
from reasongate.types import Detection

# --- Gorunmez / tehlikeli karakterler -------------------------------------
# Zero-width, bidi-override, soft-hyphen, BOM, kontrol karakterleri.
_STEALTH_CHARS = {
    "​", "‌", "‍", "⁠", "﻿",  # zero-width / BOM
    "­",                                            # soft hyphen
    "‪", "‫", "‬", "‭", "‮",    # bidi override
    "⁦", "⁧", "⁨", "⁩",              # bidi isolate
}

# --- Homoglyph: yaygin Kiril/Yunan -> Latin benzerleri --------------------
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "к": "k", "н": "h", "м": "m", "т": "t",
    "в": "b", "д": "d", "г": "r", "п": "n",
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "τ": "t", "ν": "v", "κ": "k",
    "ι": "i", "η": "n", "υ": "u", "χ": "x",
}

# --- Leetspeak katlamasi ---------------------------------------------------
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                       "7": "t", "@": "a", "$": "s", "!": "i"})

_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")


@dataclass
class NormalizationResult:
    text: str                                  # NFKC + homoglyph + stealth temizligi
    variants: List[str] = field(default_factory=list)  # ek tarama yuzeyleri
    transforms: List[str] = field(default_factory=list)  # insan-okunur "ne yapildi"
    stealth_found: bool = False                # gorunmez karakter var miydi


def _strip_stealth(text: str) -> tuple[str, int]:
    out, n = [], 0
    for ch in text:
        if ch in _STEALTH_CHARS or (unicodedata.category(ch) in {"Cf", "Cc"} and ch not in "\n\t"):
            n += 1
            continue
        out.append(ch)
    return "".join(out), n


def _fold_homoglyphs(text: str) -> tuple[str, int]:
    out, n = [], 0
    for ch in text:
        repl = _HOMOGLYPHS.get(ch)
        if repl is not None:
            out.append(repl)
            n += 1
        else:
            out.append(ch)
    return "".join(out), n


def _collapse_spaced(text: str) -> str:
    """Tek-harf token'lari ayiraclardan kurtarip birlestir:
    "i g n o r e" / "i.g.n.o.r.e" -> "ignore". Sadece >=4 tek-harf zinciri
    icin uygulanir (normal metni bozmamak icin muhafazakar).

    Kelime sinirini akilli tespit eder:
      - run'da bosluk-DISI ayrac (. - _ * |) varsa -> bosluklar kelime
        siniridir: "i.g.n.o.r.e a.l.l" -> "ignore all"
      - sadece bosluk varsa -> 2+ bosluk kelime siniridir:
        "i g n o r e   p r e v" -> "ignore prev"
    """
    def _join(m: re.Match) -> str:
        run = m.group(0)
        if re.search(r"[._\-*|]", run):
            words = run.split()                       # tek bosluk = kelime siniri
        else:
            words = re.split(r"\s{2,}", run)          # 2+ bosluk = kelime siniri
        return " ".join(re.sub(r"[\s._\-*|]+", "", w) for w in words)
    return re.sub(r"\b\w(?:[\s._\-*|]+\w\b){3,}", _join, text)


def _decode_b64(text: str) -> List[str]:
    decoded = []
    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            s = raw.decode("utf-8", errors="strict")
            if s.isprintable() and sum(c.isalpha() for c in s) >= 6:
                decoded.append(s)
        except Exception:
            continue
    return decoded


def normalize(text: str) -> NormalizationResult:
    text = text or ""
    transforms: List[str] = []

    cleaned, n_stealth = _strip_stealth(text)
    if n_stealth:
        transforms.append(f"{n_stealth} invisible/control char(s) stripped")

    cleaned = unicodedata.normalize("NFKC", cleaned)

    cleaned, n_homo = _fold_homoglyphs(cleaned)
    if n_homo:
        transforms.append(f"{n_homo} homoglyph(s) folded (Cyrillic/Greek->Latin)")

    variants: List[str] = []
    collapsed = _collapse_spaced(cleaned)
    if collapsed != cleaned:
        transforms.append("spaced / separator-broken letters joined")
        variants.append(collapsed)

    leet = cleaned.translate(_LEET)
    if leet != cleaned:
        transforms.append("leetspeak folded (0->o, 1->i, ...)")
        variants.append(leet)
        # leet + collapsed birlesimi de bir yuzey
        leet_collapsed = _collapse_spaced(leet)
        if leet_collapsed not in (leet, collapsed):
            variants.append(leet_collapsed)

    for dec in _decode_b64(cleaned):
        transforms.append("base64 payload decoded")
        variants.append(dec)

    return NormalizationResult(
        text=cleaned,
        variants=variants,
        transforms=transforms,
        stealth_found=n_stealth > 0,
    )


class NormalizationDetector(Detector):
    """Gizlenmis (obfuscated) saldiriyi yakalar.

    1) Gorunmez karakter / bidi varsa -> tek basina yuksek risk (mesru
       kullanicilar promptlarina zero-width karakter saklamaz).
    2) Normalize edilmis metni VE tum varyantlari injection dedektoruyle
       tarar; HAM metin tetiklemeyip bir varyant tetikliyorsa, bu
       "regex'i atlatmak icin gizlenmis saldiri" demektir -> risk + bonus.
    """
    name = "normalization"
    stage = "input"

    def __init__(self, threshold: float = 0.8):
        self.threshold = threshold
        from reasongate.detectors.injection import InjectionDetector
        self._inj = InjectionDetector()

    def scan(self, text: str) -> Detection:
        norm = normalize(text)
        score = 0.0
        evidence: List[str] = []

        if norm.stealth_found:
            score = max(score, 0.9)
            evidence.append("hidden/invisible character")

        raw_hit = self._inj.scan(text)
        surfaces = [norm.text, *norm.variants]
        best_obf = None
        for surf in surfaces:
            d = self._inj.scan(surf)
            if d.matches and not raw_hit.matches:
                # ham metinde gorunmeyip normalize sonrasi ortaya cikan saldiri
                if d.score > (best_obf.score if best_obf else 0.0):
                    best_obf = d

        if best_obf is not None:
            score = max(score, min(1.0, best_obf.score + 0.1))  # gizleme = niyet bonusu
            evidence.append(f"obfuscated injection ({', '.join(best_obf.matches[:3])})")

        triggered = score >= self.threshold
        if evidence:
            reason = ("Obfuscation detected: " + "; ".join(evidence)
                      + (". Transforms: " + ", ".join(norm.transforms) if norm.transforms else ""))
        else:
            reason = "No obfuscation detected."
        return Detection(self.name, triggered, round(score, 2), reason, evidence)
