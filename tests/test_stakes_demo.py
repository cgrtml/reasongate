"""Turns the stakes-demo invariant into a CI guarantee.

The demo is not a "one-off screenshot"; the three conditions below are verified on
EVERY commit, so the claim "the shield actually prevents the breach" is protected
against regressions (the mock backend is deterministic, so this runs with no API
key, in CI).
"""
from reasongate import Shield

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
