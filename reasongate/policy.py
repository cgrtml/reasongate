"""Policy: turns detections into a decision (block / flag / allow) + reason.

Threshold based and transparent. On top of per-detector thresholds there is a
fusion layer that combines several WEAK signals with a noisy-OR: none of them
crosses the block threshold alone, but a few medium signals together do.
"""
from __future__ import annotations

from typing import List, Tuple

from reasongate.types import Detection

# Noise floor for noisy-OR fusion: scores below this value (the random low
# signals of legitimate text) do not take part in the combination.
FUSION_FLOOR = 0.3


def fuse(scores: List[float], floor: float = FUSION_FLOOR) -> float:
    """Noisy-OR: combines mutually independent signals.
    fused = 1 - PROD(1 - s_i). Only signals above the floor participate, so the
    random low scores of legitimate text cannot manufacture a block."""
    contributing = [s for s in scores if s >= floor]
    prod = 1.0
    for s in contributing:
        prod *= (1.0 - s)
    return 1.0 - prod


def decide(detections: List[Detection],
           block_threshold: float = 0.8,
           flag_threshold: float = 0.5) -> Tuple[str, List[Detection]]:
    """Returns (action, triggering_detections). action in {allow, flag, block}.

    A block is reached in one of three ways:
      1) a detector's OWN calibrated threshold is crossed (d.triggered), OR
      2) a single score crosses block_threshold (Shield.block_threshold applies), OR
      3) the NOISY-OR fusion of several weak signals crosses block_threshold.
    """
    if not detections:
        return "allow", []

    triggered = [d for d in detections if d.triggered]
    over_block = [d for d in detections if d.score >= block_threshold]
    blockers = triggered or over_block
    if blockers:
        return "block", blockers

    # Fusion: several medium signals accumulating into a block.
    fused = fuse([d.score for d in detections])
    if fused >= block_threshold:
        contributors = [d for d in detections if d.score >= FUSION_FLOOR]
        return "block", contributors

    flagged = [d for d in detections if d.score >= flag_threshold]
    if flagged or fused >= flag_threshold:
        flagged = flagged or [d for d in detections if d.score >= FUSION_FLOOR]
        return "flag", flagged
    return "allow", []
