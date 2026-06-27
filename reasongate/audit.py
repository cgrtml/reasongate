"""Denetim (audit) yayini — yapisal, SIEM-dostu, sifir-bagimlilik.

Her karar (ShieldResult) bir denetim kaydina cevrilebilir (bkz. types.to_dict).
Bu modul o kayitlari bir 'sink'e yollayan hafif kancalar saglar. Varsayilan
sink Python'un standart logging'idir ("reasongate.audit" logger'i) — yani
ek bagimlilik yok ve mevcut log altyapisina (journald, ELK, Splunk forwarder)
dogrudan akar.

Tasarim ilkesi: DENETIM ASLA KAPIYI BOZMAZ. Bir audit kancasi hata atarsa
guvenlik karari yine de doner; hata yutulup ayri bir kanaldan raporlanir.

Kurumsal sink'ler (tamper-evident hash-chain, dogrudan SIEM connector,
saklama/retention politikasi) bu kanca uzerine ayri (private) katmanda kurulur.
"""
from __future__ import annotations

import logging
from typing import Callable, TextIO

from reasongate.types import ShieldResult

# Karar kayitlari icin ayrilmis logger. Uygulama bunu istedigi handler'a baglar.
audit_logger = logging.getLogger("reasongate.audit")

# Kanca hatalarini bildiren ayri logger (denetim hattindan ayrik tutulur).
_internal_logger = logging.getLogger("reasongate")

# Bir denetim kancasi: kararı alir, yan-etki olarak yayinlar (donus degeri yok).
AuditHook = Callable[[ShieldResult], None]


def log_sink(result: ShieldResult) -> None:
    """Varsayilan kanca: kararı tek-satir JSON olarak 'reasongate.audit'e yazar."""
    audit_logger.info(result.to_json())


def file_sink(path: str, *, include_output: bool = True) -> AuditHook:
    """Kararlari JSON-Lines (her satir bir karar) olarak bir dosyaya ekleyen kanca.

    SIEM ve arsiv icin standart format. Dosya append modunda acik tutulur."""
    fh: TextIO = open(path, "a", encoding="utf-8")

    def _sink(result: ShieldResult) -> None:
        fh.write(result.to_json(include_output=include_output) + "\n")
        fh.flush()

    return _sink


def safe_emit(hook: AuditHook, result: ShieldResult) -> None:
    """Kancayi cagirir; hata atarsa yutar ve ayri kanaldan loglar.
    Denetim yayini hicbir kosulda guvenlik kararini bozmamali."""
    try:
        hook(result)
    except Exception:  # pragma: no cover - savunma amacli
        _internal_logger.exception("audit kancasi basarisiz oldu (karar etkilenmedi)")
