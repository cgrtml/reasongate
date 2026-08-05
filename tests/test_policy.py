"""policy.fuse / policy.decide — the fusion math and the decision paths.

These are the deterministic, zero-dependency heart of the core; pure unit tests.
"""
from reasongate import policy
from reasongate.types import Detection


def _det(score, triggered=False, name="x"):
    return Detection(detector=name, triggered=triggered, score=score, reason="", matches=[])


# --- fuse (noisy-OR) -------------------------------------------------------

def test_fuse_empty_is_zero():
    assert policy.fuse([]) == 0.0


def test_fuse_below_floor_ignored():
    # signals below floor=0.3 do not take part in the combination
    assert policy.fuse([0.1, 0.2]) == 0.0


def test_fuse_single_signal_passes_through():
    assert policy.fuse([0.2, 0.9]) == 0.9  # 0.2 is below the floor, only 0.9 contributes


def test_fuse_noisy_or_combines():
    # 1 - (1-0.5)(1-0.5) = 0.75
    assert abs(policy.fuse([0.5, 0.5]) - 0.75) < 1e-9


def test_fuse_two_weak_signals_can_exceed_block():
    # neither crosses 0.8 alone, but their fusion does
    fused = policy.fuse([0.6, 0.6])  # 1 - 0.4*0.4 = 0.84
    assert fused > 0.8


# --- decide ----------------------------------------------------------------

def test_decide_no_detections_allows():
    action, blockers = policy.decide([])
    assert action == "allow" and blockers == []


def test_decide_triggered_blocks():
    action, blockers = policy.decide([_det(0.9, triggered=True)])
    assert action == "block" and len(blockers) == 1


def test_decide_score_over_block_threshold_blocks():
    # triggered=False, but the score is above block_threshold
    action, _ = policy.decide([_det(0.85)], block_threshold=0.8)
    assert action == "block"


def test_decide_mid_score_flags():
    action, flagged = policy.decide([_det(0.6)], block_threshold=0.8, flag_threshold=0.5)
    assert action == "flag" and flagged


def test_decide_low_score_allows():
    action, _ = policy.decide([_det(0.2)], block_threshold=0.8, flag_threshold=0.5)
    assert action == "allow"


def test_decide_fusion_blocks_multiple_weak():
    action, _ = policy.decide([_det(0.6), _det(0.6)], block_threshold=0.8)
    assert action == "block"
