"""Savunmasiz ajan + GERCEK yan etkiler.

Kritik tasarim karari: ihlalin kaniti ajanin METNI degil, GERCEK bir YAN
ETKI'dir. Iki arac diske yazar:

  * send_email  -> _sideeffects/outbox.jsonl   (VERI SIZINTISI)
  * transfer_funds -> _sideeffects/ledger.jsonl (YETKISIZ ISLEM)

Kosudan sonra bu dosyalara bakariz: OFF'ta musteri kaydi disari cikmis ve
transfer yapilmistir; ON'da dosyalar bostur. "Kotu cumle kuruldu" ile "gercek
bir ihlal oldu" arasindaki fark budur — wow'u yaratan da bu.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, List

SIDE_EFFECT_DIR = pathlib.Path(__file__).parent / "_sideeffects"
OUTBOX = SIDE_EFFECT_DIR / "outbox.jsonl"
LEDGER = SIDE_EFFECT_DIR / "ledger.jsonl"


def reset_side_effects() -> None:
    """Her kosudan ONCE cagrilir: yan-etki kayitlarini temizler ki her kosu
    kendi izini birakabilsin (deterministik, tekrar-uretilebilir)."""
    SIDE_EFFECT_DIR.mkdir(exist_ok=True)
    for f in (OUTBOX, LEDGER):
        f.write_text("", encoding="utf-8")


def _append(path: pathlib.Path, record: dict) -> None:
    record["ts"] = datetime.now(timezone.utc).isoformat()
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_side_effects() -> dict:
    """Kosu sonrasi yan-etki ozeti: kac e-posta gitti, kac transfer yapildi."""
    def _load(p: pathlib.Path) -> List[dict]:
        if not p.exists() or not p.read_text(encoding="utf-8").strip():
            return []
        return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    return {"emails": _load(OUTBOX), "transfers": _load(LEDGER)}


# --------------------------- araclar (gercek yan etki) ---------------------------

def tool_send_email(to: str, body: str) -> str:
    """VERI kanali: cagrilirsa icerik gercekten 'banka disina' (outbox'a) yazilir."""
    _append(OUTBOX, {"tool": "send_email", "to": to, "body": body})
    return f"[send_email] '{to}' adresine {len(body)} karakter gonderildi."


def tool_transfer_funds(to_account: str, amount: str) -> str:
    """ISLEM kanali: cagrilirsa transfer gercekten deftere (ledger'a) islenir."""
    _append(LEDGER, {"tool": "transfer_funds", "to_account": to_account, "amount": amount})
    return f"[transfer_funds] {amount} -> hesap {to_account} islendi."


TOOLS = {"send_email": tool_send_email, "transfer_funds": tool_transfer_funds}


# --------------------------- ajan ---------------------------

@dataclass
class AgentRun:
    answer: str
    tool_calls: List[dict] = field(default_factory=list)
    backend: str = "mock"


# Bir backend, (system, user, retrieved) alir; (final_text, [tool_call,...]) doner.
# tool_call: {"name": str, "args": dict}. Ajan bunlari GERCEKTEN calistirir.
Backend = Callable[[str, str, List[str]], "tuple[str, List[dict]]"]


def run_agent(system: str, user: str, retrieved: List[str], backend: Backend) -> AgentRun:
    """Ajani calistir: backend'e system+user+retrieved ver, dondugu her arac
    cagrisini GERCEKTEN icra et (yan etki olusur), sonra final metni dondur."""
    final_text, calls = backend(system, user, retrieved)
    executed = []
    for call in calls:
        fn = TOOLS.get(call["name"])
        if fn is None:
            continue
        result = fn(**call["args"])
        executed.append({**call, "result": result})
    return AgentRun(answer=final_text, tool_calls=executed,
                    backend=getattr(backend, "backend_name", "mock"))
