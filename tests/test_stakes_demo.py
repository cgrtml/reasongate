"""Stakes-demo invariant'i CI garantisine cevirir.

Demo bir "tek seferlik ekran goruntusu" degil; asagidaki uc sart HER commit'te
dogrulanir. Boylece "kalkan gercekten ihlali onluyor" iddiasi regresyona karsi
korunur (mock backend deterministik oldugu icin anahtarsiz, CI'da calisir).
"""
from reasongate import Shield

from examples.stakes_demo import scenario
from examples.stakes_demo.agent import (read_side_effects, reset_side_effects,
                                        run_agent)
from examples.stakes_demo.backends import mock_backend


def _breached(se) -> bool:
    return bool(se["emails"]) or bool(se["transfers"])


def test_unshielded_poisoned_causes_breach():
    """KALKAN YOK + zehirli kayit -> veri sizar ve/veya transfer yapilir."""
    reset_side_effects()
    run_agent(scenario.SYSTEM_PROMPT, scenario.USER_PROMPT,
              [scenario.POISONED_RECORD], mock_backend)
    se = read_side_effects()
    assert _breached(se), "OFF+zehirli ihlal uretmeli (demo'nun 'stakes'i)"
    assert any("acme-external" in m["to"] for m in se["emails"])
    assert any(t["to_account"] == "9900" for t in se["transfers"])


def test_shielded_poisoned_blocks_before_agent():
    """KALKAN VAR + zehirli kayit -> context bloklanir, ajan HIC calismaz."""
    shield = Shield()
    ctx = shield.scan_context(scenario.POISONED_RECORD)
    assert ctx.action == "block", "zehirli context bloklanmali"
    assert "indirect_injection" in ctx.triggered_detectors

    reset_side_effects()
    # Gate: bloklandiysa ajan calistirilmaz -> sifir yan etki.
    if ctx.action != "block":
        run_agent(scenario.SYSTEM_PROMPT, scenario.USER_PROMPT,
                  [scenario.POISONED_RECORD], mock_backend)
    se = read_side_effects()
    assert not _breached(se), "ON+zehirli hicbir yan etki uretmemeli"


def test_shielded_clean_is_allowed_no_overblock():
    """KALKAN VAR + TEMIZ kayit -> gecer (over-block yok), ajan normal calisir."""
    shield = Shield()
    inp = shield.scan_input(scenario.USER_PROMPT)
    ctx = shield.scan_context(scenario.CLEAN_RECORD)
    assert inp.action != "block"
    assert ctx.action != "block", "temiz kayit bloklanMAMALI (wedge korunur)"

    reset_side_effects()
    run = run_agent(scenario.SYSTEM_PROMPT, scenario.USER_PROMPT,
                    [scenario.CLEAN_RECORD], mock_backend)
    se = read_side_effects()
    assert not _breached(se), "temiz kayitta yan etki olmamali"
    assert "limit" in run.answer.lower(), "ajan mesru soruyu yanitlamali"
