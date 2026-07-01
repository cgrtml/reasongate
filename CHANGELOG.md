# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project aims for semantic
versioning once it reaches 1.0.

## [Unreleased]

### Added
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
