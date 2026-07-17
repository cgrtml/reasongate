# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project aims for semantic
versioning once it reaches 1.0.

## [0.2.0]

### Changed — open-core boundary
- **The ML detector, its trained model, and the provenance detector moved to the
  separate `reasongate-enterprise` add-on.** The open core is now rule-only
  (rule + normalization + indirect-injection + leakage + canary) with a **plugin
  seam**: installing `reasongate-enterprise` auto-enables ML + provenance via entry
  points (`reasongate.detectors`, `reasongate.provenance`); with nothing installed
  the core runs rule-only, silently. *If you read the arXiv preprint and are looking
  for the ML/soft-tree code, it lives in the enterprise add-on; the methodology,
  thresholds, and the reproducible benchmark harness (`eval/`, `RESULTS.md`) stay here.*
- `ShieldResult.layers` reports which layers were active (e.g. `["injection",
  "normalization"]` vs `+["ml_injection", "provenance"]`), also in the audit record.
- `reasongate.registry`: entry-point plugin loading; a failing plugin is skipped,
  never breaking the gate.

## [Unreleased]

### Added
- **Provenance-aware action gate** (`reasongate.ToolGate`, `ToolPolicy`, `GateDecision`):
  a capability-based, phrasing-independent layer for agent tool calls. It blocks a
  sensitive call when its destination is quoted from untrusted content (argument taint)
  or when it fires while untrusted content is in scope without trusted authorization
  (capability co-presence) — catching the *reworded* attacks the signature layer misses.
  Opt-in and additive: nothing runs unless tool policies are declared; the core `Shield`
  is untouched, and the gate fails closed on sensitive tools without ever raising into the
  caller. The stakes demo gains a fourth run (reworded attack → detection misses → gate
  holds), enforced as a CI invariant.
- **Input hardening**: `Shield(max_input_chars=…)` bounds oversized/pathological input
  before scanning (DoS / catastrophic-backtracking protection); truncation is recorded
  as an `input_limit` detection in the audit trail.
- Structured, auditable decision output: `ShieldResult.to_dict()` / `to_json()` with
  `decision_id`, UTC timestamp, `schema_version`, `risk_score`, `triggered_detectors`.
- Pluggable audit hook on `Shield` (`log_sink`, `file_sink`); audit never breaks the gate.
- Pluggable embedding backend via `embeddings.set_provider()` (enables on-prem encoders).
- GitHub Actions CI (Python 3.9–3.12), proving the zero-dependency core install.
- Test suite (31 tests: policy fusion, shield decisions, obfuscation, audit trail).

### Fixed
- Turkish injection patterns are now diacritic-tolerant ("önceki tüm talimatları
  yoksay", "sistem promptunu göster" now block instead of merely flagging).

## [0.1.0]
- Initial layered gate: rule + normalization + indirect-injection + leakage + canary
  detectors, policy fusion engine, and the embedding-based ML detector (optional).
