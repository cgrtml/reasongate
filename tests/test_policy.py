"""policy.fuse / policy.decide — fuzyon matematigi ve karar yollari.

Bunlar cekirdegin sifir-bagimlilik, deterministik kalbi; saf birim testleri.
"""
from reasongate import policy
from reasongate.types import Detection


def _det(score, triggered=False, name="x"):
    return Detection(detector=name, triggered=triggered, score=score, reason="", matches=[])


# --- fuse (noisy-OR) -------------------------------------------------------

def test_fuse_empty_is_zero():
    assert policy.fuse([]) == 0.0


def test_fuse_below_floor_ignored():
    # floor=0.3 altindaki sinyaller birlestirmeye katilmaz
    assert policy.fuse([0.1, 0.2]) == 0.0


def test_fuse_single_signal_passes_through():
    assert policy.fuse([0.2, 0.9]) == 0.9  # 0.2 floor altinda, sadece 0.9 katilir


def test_fuse_noisy_or_combines():
    # 1 - (1-0.5)(1-0.5) = 0.75
    assert abs(policy.fuse([0.5, 0.5]) - 0.75) < 1e-9


def test_fuse_two_weak_signals_can_exceed_block():
    # tek basina hicbiri 0.8'i gecmez ama fuzyon gecer
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
    # triggered=False ama skor block_threshold ustunde
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
