# Contributing to ReasonGate

Thanks for looking. This project is small on purpose, so a few things are worth
knowing before you open a pull request.

## The constraints that will not move

**The core has zero dependencies.** `reasongate` runs in air-gapped environments and
inside security reviews that count transitive packages. A pull request that adds a
runtime dependency to the core will be declined, however useful the library is.
Optional extras are a different conversation, and worth having.

**Every decision must carry its reason.** A detector that returns a score without
saying what it matched is not finished. The audit record is the product; the block is
a side effect.

**No network calls.** Nothing in the core reaches out. Not for model downloads, not
for telemetry, not for updates.

## What is most useful

**Attack samples that get through.** The documented recall on naturally phrased novel
attacks is 0 percent, and pretending otherwise helps nobody. A reproducible prompt that
should have been flagged and was not is more valuable here than a new feature. Open an
issue with the input, the expected action and what actually happened.

**Normalisation gaps.** Zero-width characters, homoglyphs and leetspeak are handled.
Encodings that slip past the normaliser are worth reporting.

**Documentation that corrects an overclaim.** If the README promises something the code
does not deliver, that is a bug and it is the kind I most want to hear about.

## Before you open a pull request

- `bash run_tests.sh` passes.
- New behaviour comes with a test that fails without your change.
- Detector changes state their effect on the measured recall, not just that they work.
- Public API changes are noted in `CHANGELOG.md`.

CI runs the suite on Python 3.9 through 3.12, so keep the code compatible with 3.9.

## Reporting a vulnerability

Please do not open a public issue. `SECURITY.md` has the process.

## Licence

Contributions are accepted under the Apache License 2.0, the same terms as the project.
