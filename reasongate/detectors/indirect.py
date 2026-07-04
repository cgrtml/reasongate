"""Dolayli (indirect) prompt injection dedektoru.

Prod'da en yaygin saldiri: kotu talimat KULLANICI promptunda degil,
modelin OKUDUGU icerikte gizlidir — RAG dokumani, web sayfasi, tool
ciktisi, e-posta govdesi. Kullanici masum gorunur; saldiri "veri"nin
icindedir.

Bu dedektor, retrieve edilen icerik PARCALARINI tarar ve:
  1) Var olan injection + normalization (obfuscation) dedektorlerini icerige uygular,
  2) Dolayli-enjeksiyona OZGU kaliplari arar: veri icinde asistana
     yonelen emirler, gizli HTML/markdown yorumlari, exfiltration talimatlari.

Kullanim: Shield.protect(prompt, llm_fn, context=[...]) — context icindeki
parcalar LLM'e gitmeden once taranir.
"""
from __future__ import annotations

import re
from typing import List, Tuple

from reasongate.detectors.base import Detector
from reasongate.types import Detection

# Dolayli-enjeksiyona OZGU kaliplar (veri icine gomulu asistan-emirleri).
_PATTERNS: List[Tuple[str, str, float]] = [
    (r"(ignore|disregard|forget)\s+(the\s+)?(user|above|previous|prior|all)",
     "'ignore the user/above' command inside data", 0.9),
    (r"(when|if)\s+you\s+(read|see|process|encounter)\s+this",
     "hidden instruction triggered on read", 0.85),
    (r"(do\s+not|don'?t|never)\s+(tell|inform|mention\s+to|warn)\s+(the\s+)?user",
     "instruction to hide from the user", 0.9),
    (r"(assistant|ai|model|system)\s*[:>\]]\s*",
     "fake role/system tag inside data", 0.6),
    (r"new\s+(instruction|task|directive|rule)s?\s*[:\-]",
     "'new instruction' injection inside data", 0.8),
    (r"<!--.*?(ignore|instruction|prompt|system|reveal|exfil).*?-->",
     "hidden instruction in an HTML comment", 0.85),
    (r"\[//\]:\s*#|\[comment\]:\s*#",
     "hidden markdown comment block", 0.6),
    (r"!\[[^\]]*\]\(https?://[^)]*[?&=][^)]*\)",
     "data exfiltration via markdown image (exfil URL)", 0.8),
    (r"(send|post|exfiltrate|leak|upload)\s+(the\s+)?(conversation|data|secret|key|history|prompt)",
     "instruction to send data out", 0.9),
    (r"onceki\s+(talimatlar[ıi]|kurallar[ıi])\s*[ıi]?\s*(yoksay|gozardi|unut)",
     "'ignore the above' inside data (TR)", 0.9),
    (r"kullanic[ıi]ya\s+(soyleme|haber\s+verme|bildirme)",
     "hide from the user (TR)", 0.9),

    # --- BIPIA aile-1: cikti-yonelimli meta-direktifler (SIKILASTIRILMIS) ---
    # Sinyal SPESIFIK: asistanin KENDI ciktisina yonelik DONUSUM/ENKODLAMA, ya da
    # ciktiya PROMOSYON/LINK enjeksiyonu. Belirsiz olanlar (generic 'modify your
    # response', 'translate your response') BILINCLI atildi — mesru musteri-hizmet
    # metni ("edit your response in settings") over-block edilmesin (wedge korunur).
    # Encode/encrypt/cipher + asistan-ciktisi (near-unambiguous):
    (r"(encode|encrypt|decode|encipher|cipher)\b[^.\n]{0,40}"
     r"\byour\s+(response|reply|answer|output|message)\b",
     "encode/encrypt the output (encode your response)", 0.85),
    # ciktiyi su KODLAMADA ver (dil DEGIL — base/rot/hex/morse/cipher/emoji):
    (r"\byour\s+(response|reply|answer|output|message)\b[^.\n]{0,28}"
     r"\b(in|with|as|using|into)\b[^.\n]{0,22}"
     r"(base\s?\d+|rot[\s-]?13|hex(adecimal)?|morse|[a-z]+\s+cipher|emoji)",
     "output in a given encoding (your answer in Base32)", 0.85),
    (r"\b(respond|reply|answer|write\s+back)\b[^.\n]{0,22}"
     r"\b(only\s+)?(in|with|using)\b[^.\n]{0,18}"
     r"(base\s?\d+|rot[\s-]?13|hex(adecimal)?|morse|[a-z]+\s+cipher|emoji|pig\s+latin)",
     "respond in a given encoding (respond in Base64)", 0.85),
    # emoji ile cikti donusumu:
    (r"emoji[^.\n]{0,30}\byour\s+(response|reply|answer|message|output)|"
     r"\byour\s+(response|reply|answer|message)[^.\n]{0,20}emoji",
     "convert the output to emoji", 0.85),
    # ciktiyi tersine cevir:
    (r"\byour\s+(response|reply|answer|message|output)[^.\n]{0,20}"
     r"(backward|backwards|reversed|inverted|in\s+reverse)|"
     r"(reverse|invert)\b[^.\n]{0,25}\byour\s+(response|reply|answer|message|output)",
     "reverse the output", 0.85),
    # ciktiya PROMOSYON/LINK enjeksiyonu (promo nesnesi SART; 'order ID ekle' tetiklemez):
    (r"\byour\s+(response|reply|answer|output|message)\b[^.\n]{0,75}"
     r"(https?://|www\.|\blink\b|promot|advertis|subscrib|coupon|lottery|"
     r"investment|\boffer\b|\bdeal\b|\bbrand\b|newsletter|antivirus)"
     r"|(https?://|www\.|\blink\b|promot|advertis|subscrib|coupon|lottery|"
     r"investment|newsletter|antivirus)[^.\n]{0,75}"
     r"\bto\s+(your|the)\s+(response|reply|answer|output|message)\b",
     "inject promotion/link into the output", 0.8),
]


class IndirectInjectionDetector(Detector):
    name = "indirect_injection"
    stage = "input"   # context, LLM cagrilmadan once taranir

    def __init__(self, block_score: float = 0.8, scan_obfuscation: bool = True):
        self._compiled = [(re.compile(p, re.IGNORECASE | re.DOTALL), label, w)
                          for p, label, w in _PATTERNS]
        self.block_score = block_score
        # Dolayli icerik de gizlenebilir; obfuscation katmanini uygula.
        self._norm = None
        if scan_obfuscation:
            from reasongate.detectors.normalize import NormalizationDetector
            self._norm = NormalizationDetector()

    def scan(self, text: str) -> Detection:
        text = text or ""
        matches: List[str] = []
        max_w = 0.0
        for rx, label, w in self._compiled:
            if rx.search(text):
                matches.append(label)
                max_w = max(max_w, w)

        # icerige gizlenmis (obfuscated) dogrudan-enjeksiyon da dolayli saldiridir
        if self._norm is not None:
            nd = self._norm.scan(text)
            if nd.matches:
                matches.extend(f"[hidden] {m}" for m in nd.matches)
                max_w = max(max_w, nd.score)

        triggered = max_w >= self.block_score
        reason = (f"{len(matches)} indirect-injection signal(s) in the retrieved content."
                  if matches else "No indirect-injection signal in the content.")
        return Detection(self.name, triggered, round(max_w, 2), reason, matches)
