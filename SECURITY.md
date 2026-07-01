# Security Policy

ReasonGate is a security tool; we hold it to a security tool's standard.

## Supported versions

The `0.1.x` line receives security fixes. Pre-1.0 the API may change; pin a version
in production.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public issue.

- Email: **cagritemelusa@gmail.com** with subject `SECURITY: reasongate`.
- Include a description, affected version, and a minimal reproduction if possible.

We aim to acknowledge within 5 business days and to coordinate a fix and disclosure
timeline with you. Please give us reasonable time to remediate before public disclosure.

## Scope notes

- **The gate is one layer, not a guarantee.** ReasonGate reduces prompt-injection /
  jailbreak risk; it does not eliminate it. Run it with the model's own safety
  training behind it. Recall is never 100%.
- **Adversarial input hardening.** The core parses untrusted text; oversized or
  pathological inputs should be bounded by the caller (see input limits in the
  deployment guide). Report any input that causes excessive CPU/memory as a
  vulnerability.
- **No telemetry.** The core makes no network calls and sends us nothing.
