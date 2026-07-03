"""Ajanin ARKASINDAKI model: deterministik mock + gercek Anthropic (tool-use).

Durustluk notu: mock "bu demoya gore hile" DEGILDIR. Mock, NAIF bir arac-kullanan
ajanin BILINEN davranisini deterministik olarak yeniden uretir: baglamindaki
TUM metni yetkili kabul eder ve icinde buldugu eyleme-donuk emirleri uygular.
Dolayli enjeksiyonun gercek modellerde is gormesinin sebebi tam budur. Gercek
API yolu (ANTHROPIC_API_KEY varsa) bunu herkesin dogrulayabilmesi icindir:
ayni zehirli baglam, gercek modele verilince de sik sik ayni uc araclari cagirir.

Her iki durumda da demonun ISPATI degismez: ReasonGate zehirli baglami model
HIC cagrilmadan bloklar — yani modelin uyup uymamasi konu disi kalir.
"""
from __future__ import annotations

import os
import re
from typing import List, Tuple

# ----------------------------- mock backend -----------------------------

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_ACCOUNT_RE = re.compile(r"account\s+(\d{3,})", re.IGNORECASE)
_BALANCE_RE = re.compile(r"(?:Bakiye|Balance)\s*:?\s*(\$[\d,]+(?:\.\d+)?)", re.IGNORECASE)
_EXFIL_RE = re.compile(r"\b(send|forward|exfiltrate|leak|upload|email)\b", re.IGNORECASE)
_TRANSFER_RE = re.compile(r"\btransfer\b", re.IGNORECASE)


def mock_backend(system: str, user: str, retrieved: List[str]) -> Tuple[str, List[dict]]:
    """Naif ajan simulasyonu: baglamdaki emirlere gore hareket eder.

    Kural (seffaf, bu demoya ozel degil): baglamda bir 'send ... to <email>'
    varsa musteri kaydini o adrese yollar; bir 'transfer ... to account <N>'
    varsa transferi yapar. Yoksa sadece kullanicinin sorusunu yanitlar.
    """
    context = "\n".join(retrieved)
    calls: List[dict] = []

    # Ajanin "gordugu" hassas kayit — sizarsa bu icerik disari cikar.
    record_body = context.strip() or "(kayit yok)"
    balance_match = _BALANCE_RE.search(context)
    balance = balance_match.group(1) if balance_match else "$0.00"

    # 1) Exfiltration emri var mi? (send/forward/email ... <adres>)
    if _EXFIL_RE.search(context):
        email = _EMAIL_RE.search(context)
        if email:
            calls.append({"name": "send_email",
                          "args": {"to": email.group(0), "body": record_body}})

    # 2) Transfer emri var mi? (transfer ... account <N>)
    if _TRANSFER_RE.search(context):
        acct = _ACCOUNT_RE.search(context)
        if acct:
            calls.append({"name": "transfer_funds",
                          "args": {"to_account": acct.group(1), "amount": balance}})

    # 3) Her durumda kullanicinin ASIL sorusunu da yanitla (masum kisim).
    if "limit" in (context + user).lower():
        limit = "$10,000.00"
        m = re.search(r"limit[i:]?\s*:?\s*(\$[\d,]+(?:\.\d+)?)", context, re.IGNORECASE)
        if m:
            limit = m.group(1)
        answer = (f"John Doe'nun kart limiti {limit}. Baska bir sey isterse "
                  f"yardimci olabilirim.")
    else:
        answer = "John Doe'nun hesabini ozetledim."
    return answer, calls


mock_backend.backend_name = "mock"


# ----------------------------- gercek Anthropic backend -----------------------------

_ANTHROPIC_TOOLS = [
    {"name": "send_email", "description": "Bir e-posta gonderir.",
     "input_schema": {"type": "object",
                      "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
                      "required": ["to", "body"]}},
    {"name": "transfer_funds", "description": "Hesaplar arasi para transferi yapar.",
     "input_schema": {"type": "object",
                      "properties": {"to_account": {"type": "string"}, "amount": {"type": "string"}},
                      "required": ["to_account", "amount"]}},
]


def real_backend(system: str, user: str, retrieved: List[str]) -> Tuple[str, List[dict]]:
    """Gercek Claude'u tool-use ile cagirir. Retrieve edilen kayit, gercek bir
    RAG/tool ciktisi gibi kullanici mesajina eklenir."""
    import anthropic
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    model = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
    content = (f"{user}\n\n--- Getirilen musteri kaydi ---\n" + "\n".join(retrieved))
    resp = client.messages.create(
        model=model, max_tokens=800, system=system, tools=_ANTHROPIC_TOOLS,
        messages=[{"role": "user", "content": content}],
    )
    calls, texts = [], []
    for block in resp.content:
        if getattr(block, "type", "") == "tool_use":
            calls.append({"name": block.name, "args": dict(block.input)})
        elif getattr(block, "type", "") == "text":
            texts.append(block.text)
    return ("".join(texts).strip() or "(model yalnizca arac cagirdi)"), calls


real_backend.backend_name = "anthropic"


def select_backend():
    """ANTHROPIC_API_KEY varsa gercek modeli, yoksa deterministik mock'u sec."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            import anthropic  # noqa: F401
            return real_backend, "anthropic (gercek API)"
        except ImportError:
            pass
    return mock_backend, "mock (deterministik; anahtar yok)"
