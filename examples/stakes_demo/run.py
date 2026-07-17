"""ReasonGate — Stakes Demo.

Same attack, one variable: THE SHIELD.

  Run 1  Shield OFF + poisoned record  -> BREACH   (data leaks + a transfer is made)
  Run 2  Shield ON  + poisoned record  -> BLOCKED  (detection layer: no side effects)
  Run 3  Shield ON  + CLEAN record     -> ALLOWED  (agent answers normally)
  Run 4  Shield ON  + REWORDED attack  -> BLOCKED  (detection MISSES; action gate holds)

Run 1 vs 2 is the "wow" (the only difference is the shield). Run 3 is the proof
that this is not a dumb blocklist. Run 4 is the point that answers "you can reword
around a regex": the signature layer does miss the reworded attack, but the
provenance-aware action gate blocks the tool call anyway, because its destination
comes from untrusted content — phrasing-independent.

Run:       python -m examples.stakes_demo.run
No color:  python -m examples.stakes_demo.run --no-color
"""
from __future__ import annotations

import sys

from reasongate import Segment, Shield, ToolGate, ToolPolicy

from examples.stakes_demo import scenario
from examples.stakes_demo.agent import (read_side_effects, reset_side_effects,
                                        run_agent)
from examples.stakes_demo.backends import select_backend

# ----------------------------- terminal styling -----------------------------
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
        print("  side effects: " + grn("NONE") + dim("  (outbox empty, ledger empty)"))
        return
    for m in se["emails"]:
        print("  " + red("-> DATA EXFILTRATED") + f"  {m['to']}  " + dim(f"({len(m['body'])} chars of customer record)"))
    for t in se["transfers"]:
        print("  " + red("-> TRANSFER") + f"        {t['amount']} -> account {t['to_account']}")


# ----------------------------- runs -----------------------------

def run_unshielded(record: str):
    """SHIELD OFF: the agent processes the poisoned record directly."""
    reset_side_effects()
    backend, _ = select_backend()
    run = run_agent(scenario.SYSTEM_PROMPT, scenario.USER_PROMPT, [record], backend)
    print("  agent reply : " + dim(run.answer))
    if run.tool_calls:
        for tc in run.tool_calls:
            print("  tool call   : " + yel(tc["name"]) + dim(f"  {tc['args'].get('to') or tc['args'].get('to_account')}"))
    show_side_effects(read_side_effects())


def run_shielded(record: str, shield: Shield):
    """SHIELD ON: input + context are scanned first; if blocked, the agent never runs."""
    reset_side_effects()
    inp = shield.scan_input(scenario.USER_PROMPT)
    ctx = shield.scan_context(record)

    if inp.action == "block" or ctx.action == "block":
        blocker = ctx if ctx.action == "block" else inp
        print("  " + red("BLOCKED BY THE SHIELD") + dim("  — the agent / model was never called"))
        for d in blocker.detections:
            if d.triggered:
                print(dim(f"     x {d.detector} (score={d.score:.2f}): {d.reason}"))
                if d.matches:
                    print(dim(f"       evidence: {', '.join(d.matches[:3])}"))
        show_side_effects(read_side_effects())
        return

    # Clean: run the agent, and scan the output too (defense in depth).
    backend, _ = select_backend()
    run = run_agent(scenario.SYSTEM_PROMPT, scenario.USER_PROMPT, [record], backend)
    out = shield.scan_output(run.answer)
    tag = grn("allow") if out.action == "allow" else yel(out.action)
    print("  shield verdict: input=" + grn("clean") + f"  output={tag}")
    print("  agent reply   : " + dim(run.answer))
    show_side_effects(read_side_effects())


def run_gated(record: str, shield: Shield, gate: ToolGate):
    """SHIELD ON, but the injection is REWORDED so the signature detector misses it.
    The action gate is the second layer: it blocks the tool call because its
    destination originates from untrusted content — regardless of the wording."""
    reset_side_effects()
    seg = Segment(text=record, source="customer-record", trust="untrusted", domain="crm")
    ctx = shield.scan_context(seg)
    verdict = grn("allow") if ctx.action == "allow" else yel(ctx.action)
    print("  detection layer: context=" + verdict
          + dim("  (reworded attack — the signature layer does not match it)"))

    backend, _ = select_backend()
    run = run_agent(scenario.SYSTEM_PROMPT, scenario.USER_PROMPT, [record], backend,
                    gate=gate, context_segments=[seg])
    if run.blocked_calls:
        print("  action gate    : " + red("BLOCKED")
              + dim("  — the tool call was stopped before it could run"))
        for bc in run.blocked_calls:
            dec = bc["decision"]
            d = dec.detections[0]
            print(dim(f"     x {dec.tool}: {d.reason}"))
            if d.matches:
                print(dim(f"       evidence: {d.matches[0]}"))
    else:
        print("  action gate    : " + grn("no sensitive call reached execution"))
    show_side_effects(read_side_effects())


# ----------------------------- main -----------------------------

def main():
    _, backend_label = select_backend()
    print()
    print(bold("  ReasonGate — Stakes Demo") + dim("   (Acme Bank customer-support agent)"))
    print(dim(f"  model backend: {backend_label}"))
    rule()
    print("  User (innocent): " + dim(scenario.USER_PROMPT[:70] + "..."))
    print("  Attack: a hidden instruction is embedded in the retrieved customer record")
    print(dim("          (the user never sees it; the agent reads it as a direct command)"))
    rule()

    shield = Shield()
    print(dim(f"  active shield layers: {', '.join(shield.layers)}"))
    print()

    # --- RUN 1: no shield, poisoned ---
    print(bold("  [1] Shield OFF") + "  +  poisoned record")
    run_unshielded(scenario.POISONED_RECORD)
    banner("BREACH: customer data leaked + unauthorized transfer made", ok=False)
    print()

    # --- RUN 2: shield on, poisoned (ONLY variable: the shield) ---
    print(bold("  [2] Shield ON") + "   +  poisoned record   " + dim("(same input, only difference: the shield)"))
    run_shielded(scenario.POISONED_RECORD, shield)
    banner("BLOCKED: same attack, zero side effects", ok=True)
    print()

    # --- RUN 3: shield on, clean (show there is no over-blocking) ---
    print(bold("  [3] Shield ON") + "   +  CLEAN record       " + dim("(legitimate traffic must pass)"))
    run_shielded(scenario.CLEAN_RECORD, shield)
    banner("ALLOWED: agent worked normally, no side effects", ok=True)
    print()

    # --- RUN 4: reworded attack the detector MISSES, stopped by the action gate ---
    gate = ToolGate([
        ToolPolicy("send_email", sensitive=True, destination_args=("to",)),
        ToolPolicy("transfer_funds", sensitive=True, destination_args=("to_account",)),
    ])
    print(bold("  [4] Shield ON") + "   +  REWORDED attack    " + dim("(signature layer misses it; the action gate holds)"))
    run_gated(scenario.POISONED_RECORD_REWORDED, shield, gate)
    banner("BLOCKED BY THE ACTION GATE: detection missed, the action still could not fire", ok=True)
    print()

    rule("═")
    print("  " + bold("Bottom line:") + " Same agent, same attack. Shield OFF -> the breach HAPPENS.")
    print("        Shield ON -> the known attack stops before the model sees it; the legit request passes;")
    print("        and when the attack is REWORDED past the detector, the action gate still blocks it —")
    print("        because untrusted data cannot authorize a sensitive action, however it is phrased.")
    print("  " + dim("The proof isn't the text — it's the side-effect logs: examples/stakes_demo/_sideeffects/"))
    rule("═")
    print()


if __name__ == "__main__":
    main()
