"""ReasonGate — Stakes Demo.

Ayni saldiri, tek degisken: KALKAN.

  Kosu 1  Shield OFF + zehirli kayit  -> IHLAL   (veri sizar + transfer yapilir)
  Kosu 2  Shield ON  + zehirli kayit  -> BLOKLU  (hicbir yan etki yok)
  Kosu 3  Shield ON  + TEMIZ kayit    -> IZIN    (ajan normal yanitlar)

Kosu 1 vs 2 "wow"u verir. Kosu 3 "aptal blocklist degil"in kanitidir.

Calistir:  python -m examples.stakes_demo.run
Renksiz  :  python -m examples.stakes_demo.run --no-color
"""
from __future__ import annotations

import sys

from reasongate import Shield

from examples.stakes_demo import scenario
from examples.stakes_demo.agent import (read_side_effects, reset_side_effects,
                                        run_agent)
from examples.stakes_demo.backends import select_backend

# ----------------------------- terminal susu -----------------------------
_COLOR = "--no-color" not in sys.argv


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def red(t): return c(t, "1;31")
def grn(t): return c(t, "1;32")
def yel(t): return c(t, "1;33")
def dim(t): return c(t, "2")
def bold(t): return c(t, "1")


def rule(char="─", n=64):
    print(dim(char * n))


def banner(text, ok: bool):
    body = grn(f"  {text}  ") if ok else red(f"  {text}  ")
    line = grn("▛" + "▀" * (len(text) + 4) + "▜") if ok else red("▛" + "▀" * (len(text) + 4) + "▜")
    bot = grn("▙" + "▄" * (len(text) + 4) + "▟") if ok else red("▙" + "▄" * (len(text) + 4) + "▟")
    print("  " + line)
    print("  " + (grn("▌") if ok else red("▌")) + body + (grn("▐") if ok else red("▐")))
    print("  " + bot)


def show_side_effects(se: dict):
    n_mail, n_tx = len(se["emails"]), len(se["transfers"])
    if n_mail == 0 and n_tx == 0:
        print("  yan etki: " + grn("YOK") + dim("  (outbox bos, ledger bos)"))
        return
    for m in se["emails"]:
        print("  " + red("✉ VERI DISARI") + f"  {m['to']}  " + dim(f"({len(m['body'])} karakter musteri kaydi)"))
    for t in se["transfers"]:
        print("  " + red("$ TRANSFER") + f"     {t['amount']} -> hesap {t['to_account']}")


# ----------------------------- kosular -----------------------------

def run_unshielded(record: str):
    """KALKAN YOK: ajan zehirli kaydi dogrudan isler."""
    reset_side_effects()
    backend, _ = select_backend()
    run = run_agent(scenario.SYSTEM_PROMPT, scenario.USER_PROMPT, [record], backend)
    print("  ajan cevabi : " + dim(run.answer))
    if run.tool_calls:
        for tc in run.tool_calls:
            print("  arac cagrisi: " + yel(tc["name"]) + dim(f"  {tc['args'].get('to') or tc['args'].get('to_account')}"))
    show_side_effects(read_side_effects())


def run_shielded(record: str, shield: Shield):
    """KALKAN VAR: once girdi+context taranir; bloklaniyorsa ajan HIC calismaz."""
    reset_side_effects()
    inp = shield.scan_input(scenario.USER_PROMPT)
    ctx = shield.scan_context(record)

    if inp.action == "block" or ctx.action == "block":
        blocker = ctx if ctx.action == "block" else inp
        print("  " + red("⛔ KALKAN GIRDIYI DURDURDU") + dim("  — ajan/model HIC cagrilmadi"))
        for d in blocker.detections:
            if d.triggered:
                print(dim(f"     ✗ {d.detector} (skor={d.score:.2f}): {d.reason}"))
                if d.matches:
                    print(dim(f"       kanit: {', '.join(d.matches[:3])}"))
        show_side_effects(read_side_effects())
        return

    # Temiz: ajani calistir, ciktiyi da tara (savunma derinligi).
    backend, _ = select_backend()
    run = run_agent(scenario.SYSTEM_PROMPT, scenario.USER_PROMPT, [record], backend)
    out = shield.scan_output(run.answer)
    tag = grn("izin") if out.action == "allow" else yel(out.action)
    print("  kalkan karari: girdi=" + grn("temiz") + f"  cikti={tag}")
    print("  ajan cevabi  : " + dim(run.answer))
    show_side_effects(read_side_effects())


# ----------------------------- main -----------------------------

def main():
    _, backend_label = select_backend()
    print()
    print(bold("  ReasonGate — Stakes Demo") + dim("   (Acme Bank musteri-hizmet ajani)"))
    print(dim(f"  model backend: {backend_label}"))
    rule()
    print("  Kullanici (masum): " + dim(scenario.USER_PROMPT[:70] + "..."))
    print("  Saldiri: zehirli musteri kaydinin destek-notuna gizli talimat gomulu")
    print(dim("           (kullanici bunu gormez; ajan icin dogrudan emir gibi okunur)"))
    rule()

    shield = Shield()
    print(dim(f"  aktif kalkan katmanlari: {', '.join(shield.layers)}"))
    print()

    # --- KOSU 1: kalkan yok, zehirli ---
    print(bold("  [1] Shield OFF") + "  +  zehirli kayit")
    run_unshielded(scenario.POISONED_RECORD)
    banner("IHLAL: musteri verisi sizdi + izinsiz transfer yapildi", ok=False)
    print()

    # --- KOSU 2: kalkan var, zehirli (TEK degisken: kalkan) ---
    print(bold("  [2] Shield ON") + "   +  zehirli kayit   " + dim("(ayni girdi, tek fark: kalkan)"))
    run_shielded(scenario.POISONED_RECORD, shield)
    banner("BLOKLANDI: ayni saldiri, sifir yan etki", ok=True)
    print()

    # --- KOSU 3: kalkan var, temiz (over-block olmadigini goster) ---
    print(bold("  [3] Shield ON") + "   +  TEMIZ kayit     " + dim("(mesru trafik engellenmemeli)"))
    run_shielded(scenario.CLEAN_RECORD, shield)
    banner("IZIN VERILDI: ajan normal calisti, yan etki yok", ok=True)
    print()

    rule("═")
    print("  " + bold("Ozet:") + " Ayni ajan, ayni saldiri. Kalkan KAPALIyken ihlal GERCEKLESIR;")
    print("        ACIKken ayni saldiri model gorulmeden durur; mesru istek gecer.")
    print("  " + dim("Kanit metinde degil, yan-etki kayitlarinda: examples/stakes_demo/_sideeffects/"))
    rule("═")
    print()


if __name__ == "__main__":
    main()
