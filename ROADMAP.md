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
- **Multilingual**: the rule patterns are English, so non-English injection is uncovered
  by construction. Honest benchmarking here is blocked on data, not code: the only real
  parallel multilingual set (MultiJail) tests harmful-content jailbreaks, not instruction
  injection (the core detects ~0% of it in *every* language, English included, because it
  is off-threat), and no real native prompt-injection corpus exists for other languages.
  Machine translation is excluded on purpose (synthetic). Multilingual semantic recall is
  therefore an enterprise-embedding concern; the near-term open-core step is honest
  per-language coverage numbers once a real corpus exists, not a synthetic benchmark.

## Longer term
- **Continuous adversarial regression**: a red-team harness that re-measures as attack
  techniques evolve.
- **Multimodal**: detection of prompt injection hidden in images.

The enterprise, on-prem, and compliance features live in a separate offering.
