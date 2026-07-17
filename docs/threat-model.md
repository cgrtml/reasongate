# Threat model & design note: a provenance-aware action gate for tool-using agents

*A short, honest design note on the layer that answers "you can just reword the
attack." It states the threat, why text-detection is structurally insufficient,
and the capability-based control ReasonGate uses instead — with its guarantees and,
just as important, its non-guarantees.*

## 1. The threat: indirect prompt injection against agents

The interesting attack surface is no longer a user typing a jailbreak. It is an
autonomous, tool-carrying agent that reads **untrusted content** — a retrieved
document, an email body, a web page, a tool result — and then takes an **action**
(sends mail, moves money, deletes a file, executes code). The malicious instruction
lives in the *data the agent retrieves*, not in the user's request. The user is
innocent; the agent treats the retrieved text as authoritative and acts on it.

The asset to protect is therefore the **action**, not the text. "The model said
something bad" and "the agent actually exfiltrated a record" are different events;
only the second is a breach. This document is about preventing the second.

## 2. Why detection alone is structurally insufficient

A signature/ML detector answers *"is this text an injection?"* That question can be
lost by rewording. A rule layer catches phrasings it has a pattern for; a classifier
catches distributions it has seen. Neither catches a *novel* rephrasing of the same
intent — and an attacker gets unlimited attempts to find one.

This is not a tuning problem; it is the nature of matching text against an unbounded
space of paraphrases. ReasonGate is explicit about it: on naturally-phrased attacks
the rule core catches **0%** (see [RESULTS.md](../RESULTS.md)), and even the ML add-on
tops out well short of 100% out-of-distribution. A defense that depends on recognizing
the attack text will always have a reworded variant that gets through.

## 3. The principle: constrain the action, not the text

The robust move is to stop trying to *recognize the attack* and instead *constrain
what an action is allowed to do given where it came from*. This is the capability-
based view of prompt-injection defense — closely related to Simon Willison's framing
of **the "lethal trifecta"** (private data + untrusted content + an exfiltration
channel, all reachable in one context) and to control-/capability-flow approaches
such as the dual-LLM pattern and CaMeL. Break any leg of the trifecta and the breach
cannot complete, *regardless of how the injection is worded*.

ReasonGate operationalizes one concrete, deployable slice of this: a **provenance-
aware action gate** that sits between a proposed tool call and its execution.

## 4. Design

### 4.1 Trust model

The integrating application labels the data the agent sees with provenance, using
`Segment(text, source, trust, domain)`. `trust` is `"trusted"` (the authorized
principal — e.g. the signed-in staff user, the system prompt) or `"untrusted"`
(anything retrieved: RAG documents, tool output, web, email). A plain string with no
provenance is treated as **untrusted** (fail-safe default).

Tools are declared with `ToolPolicy(name, sensitive, destination_args,
requires_authorization)`. A *sensitive* tool is irreversible or high-authority
(transfer, external send, delete, code execution). `destination_args` names the
arguments that carry a destination (recipient, account, URL, path).

### 4.2 Two signals, strongest first

Given a proposed call `{"name", "args"}`, the untrusted segments in scope, and
whether the trusted principal explicitly authorized *this* action:

1. **Argument taint (precise, phrasing-independent).** If a sensitive call's
   destination argument *appears in* untrusted content, block it. The exfiltration
   target (an attacker's email, an account number) is quoted from the attacker-
   controlled data; no rewording of the surrounding instruction can hide that the
   *destination itself* originates from untrusted text. Matching is over casefolded,
   whitespace-normalized text, with a whole-token rule for very short values.

2. **Capability co-presence (coarse backstop).** If a sensitive call fires while any
   untrusted content is in scope and nothing trusted authorized it, block it — the
   lethal-trifecta condition, even when the destination is not literally quoted.

An explicit trusted authorization bypasses both (a legitimate, staff-initiated
transfer proceeds). A non-sensitive tool is never gated.

### 4.3 Fail-safe & non-intrusive

The gate is opt-in and additive: with no policies declared it does nothing, and the
core `Shield` is untouched. It never raises into the calling agent; on an unexpected
internal error it fails **closed** for sensitive tools and open for the rest. Every
decision is explainable (`GateDecision.explain()`), so a block is auditable, not a
black box.

## 5. What it guarantees — and what it does not

**Guarantees (given the contract in §6):** untrusted data cannot escalate into a
gated action, however the injection is worded. A reworded attack that defeats the
detector still cannot wire funds to an account, or send a record to an address, that
came from untrusted content.

**Non-guarantees — stated plainly:**

- **It is not a detector and not a completeness claim.** It constrains *sensitive,
  declared* actions. Tools you do not mark sensitive are not gated.
- **Argument taint is a heuristic**, based on value-presence in untrusted text. An
  attacker who can induce a sensitive call whose destination is *not* drawn from the
  untrusted text falls through to the coarser co-presence rule — which is deliberately
  conservative and can over-gate (see below).
- **Co-presence can over-gate.** Blocking every sensitive action while any untrusted
  content is in scope is safe but blunt; production use wants explicit authorization
  flows so legitimate sensitive actions are not gated away.
- **Provenance is the app's responsibility.** If the integrator mislabels untrusted
  data as trusted, the gate is blind. Garbage provenance in, no protection out.

## 6. The honest contract

This is capability-based defense, not magic. In exchange for a guarantee detection
cannot give, the integrator must (a) declare which tools are sensitive and which
arguments are destinations, and (b) pass truthful provenance for the data the agent
saw. That is the whole trade: a small, explicit contract for a phrasing-independent
property.

## 7. Evaluation as an executable invariant

The claim is pinned, not asserted. `examples/stakes_demo` runs a bank-support agent
with real, on-disk side effects (an outbox and a ledger). Its fourth scenario feeds a
**reworded** attack the detector misses; the CI invariant
(`tests/test_stakes_demo.py`) verifies that (i) detection does not block it, (ii)
without the gate the agent breaches, and (iii) with the gate there are **zero** side
effects — on every commit. A mirror test verifies the gate does **not** over-block a
legitimate, authorized transfer.

## 8. Limitations & future work

- **Taint propagation.** Today taint is single-hop (does the argument appear in an
  untrusted segment?). Multi-hop dataflow — an untrusted value transformed before it
  reaches a tool argument — is future work.
- **Channel coverage.** The gate reasons about the *provenance* the app supplies; it
  does not itself discover untrusted channels.
- **Authorization UX.** A production deployment needs a real trusted-authorization
  path (human-in-the-loop, capability tokens) so co-presence does not force a choice
  between over-blocking and disabling the backstop.
- **Formalization.** The relationship between this gate and a full information-flow /
  capability system (CaMeL-style) is worth making precise; this note is the practical,
  deployable slice, not the formal treatment.

---

*This is a design note, not a peer-reviewed paper. It documents the reasoning behind
the `reasongate.ToolGate` layer honestly, including where it stops. Corrections and
adversarial reading are welcome — open an issue.*
