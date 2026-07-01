# Roadmap

Direction for the open core. Priorities are ordered; dates are intentionally omitted.

## Near term
- **Input hardening**: enforce a max input size and guard against pathological /
  catastrophic-backtracking inputs (a guard must not be DoS-able).
- **Score calibration**: isotonic/Platt calibration for the ML detector to spread the
  saturated score distribution and make thresholds reliable.
- **Over-defense**: reduce false positives on trigger-word-heavy benign text with
  hard-negative training data.
- **Tooling**: ruff + mypy + coverage in CI; CHANGELOG discipline.

## Medium term
- **Multi-turn**: benchmark and harden `ConversationShield` (accumulated risk).
- **Agent / tool-call injection**: detectors for function-call arguments and tool output.
- **Docs**: API reference, deployment guide, threat model.
- **Multilingual**: expand beyond English/Turkish with published per-language metrics.

## Longer term
- **Continuous adversarial regression**: a red-team harness that re-measures as attack
  techniques evolve.
- **Multimodal**: detection of prompt injection hidden in images.

The enterprise, on-prem, and compliance features live in a separate offering.
