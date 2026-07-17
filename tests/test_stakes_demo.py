"""Turns the stakes-demo invariant into a CI guarantee.

The demo is not a "one-off screenshot"; the three conditions below are verified on
EVERY commit, so the claim "the shield actually prevents the breach" is protected
against regressions (the mock backend is deterministic, so this runs with no API
key, in CI).
"""
from reasongate import Segment, Shield, ToolGate, ToolPolicy

from examples.stakes_demo import scenario
from examples.stakes_demo.agent import (read_side_effects, reset_side_effects,
                                        run_agent)
from examples.stakes_demo.backends import mock_backend


def _breached(se) -> bool:
    return bool(se["emails"]) or bool(se["transfers"])


def test_unshielded_poisoned_causes_breach():
    """NO SHIELD + poisoned record -> data leaks and/or a transfer is made."""
    reset_side_effects()
    run_agent(scenario.SYSTEM_PROMPT, scenario.USER_PROMPT,
              [scenario.POISONED_RECORD], mock_backend)
    se = read_side_effects()
    assert _breached(se), "OFF+poisoned must produce a breach (the demo's 'stakes')"
    assert any("acme-external" in m["to"] for m in se["emails"])
    assert any(t["to_account"] == "9900" for t in se["transfers"])


def test_shielded_poisoned_blocks_before_agent():
    """SHIELD ON + poisoned record -> context is blocked, the agent never runs."""
    shield = Shield()
    ctx = shield.scan_context(scenario.POISONED_RECORD)
    assert ctx.action == "block", "poisoned context must be blocked"
    assert "indirect_injection" in ctx.triggered_detectors

    reset_side_effects()
    # Gate: if blocked, the agent is not run -> zero side effects.
    if ctx.action != "block":
        run_agent(scenario.SYSTEM_PROMPT, scenario.USER_PROMPT,
                  [scenario.POISONED_RECORD], mock_backend)
    se = read_side_effects()
    assert not _breached(se), "ON+poisoned must produce no side effects"


def test_shielded_clean_is_allowed_no_overblock():
    """SHIELD ON + CLEAN record -> passes (no over-block), the agent runs normally."""
    shield = Shield()
    inp = shield.scan_input(scenario.USER_PROMPT)
    ctx = shield.scan_context(scenario.CLEAN_RECORD)
    assert inp.action != "block"
    assert ctx.action != "block", "clean record must NOT be blocked (the wedge is preserved)"

    reset_side_effects()
    run = run_agent(scenario.SYSTEM_PROMPT, scenario.USER_PROMPT,
                    [scenario.CLEAN_RECORD], mock_backend)
    se = read_side_effects()
    assert not _breached(se), "clean record must produce no side effects"
    assert "limit" in run.answer.lower(), "the agent must answer the legitimate question"


def _demo_gate() -> ToolGate:
    return ToolGate([
        ToolPolicy("send_email", sensitive=True, destination_args=("to",)),
        ToolPolicy("transfer_funds", sensitive=True, destination_args=("to_account",)),
    ])


def test_reworded_attack_slips_past_detection_but_is_stopped_by_the_gate():
    """The point of the second layer: the detector MISSES the reworded attack, yet the
    action gate still prevents the breach — the invariant that answers 'reword the regex'."""
    shield = Shield()
    ctx = shield.scan_context(scenario.POISONED_RECORD_REWORDED)
    # 1) Detection genuinely misses it (this is the honest premise, not a failure).
    assert ctx.action != "block", "reworded attack is expected to slip past signatures"

    # 2) Without the gate, the naive agent breaches on the reworded record.
    reset_side_effects()
    run_agent(scenario.SYSTEM_PROMPT, scenario.USER_PROMPT,
              [scenario.POISONED_RECORD_REWORDED], mock_backend)
    assert _breached(read_side_effects()), "no gate -> reworded attack still breaches"

    # 3) With the gate, the same reworded attack causes zero side effects.
    reset_side_effects()
    seg = Segment(text=scenario.POISONED_RECORD_REWORDED,
                  source="customer-record", trust="untrusted", domain="crm")
    run = run_agent(scenario.SYSTEM_PROMPT, scenario.USER_PROMPT,
                    [scenario.POISONED_RECORD_REWORDED], mock_backend,
                    gate=_demo_gate(), context_segments=[seg])
    assert not _breached(read_side_effects()), "gate must stop the reworded attack"
    assert run.blocked_calls, "the gate must have blocked at least one tool call"


def test_gate_does_not_overblock_a_legitimate_authorized_action():
    """The mirror invariant: a legitimate transfer explicitly authorized by trusted
    staff (no untrusted content in scope) must still go through."""
    gate = _demo_gate()
    trusted = Segment(text="Please transfer $500 to account 12345 for John.",
                      source="staff-console", trust="trusted")
    dec = gate.authorize({"name": "transfer_funds", "args": {"to_account": "12345", "amount": "$500"}},
                         context=[trusted], authorized=True)
    assert dec.allowed, "authorized, trusted-origin action must not be over-blocked"
