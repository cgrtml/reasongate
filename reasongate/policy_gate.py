"""Judge a request against the deployment's own policy — the input the filter never had.

Measured on the real corpus (`docs/coverage-gaps.md`), 54% of the attacks the rule core
misses carry no attack marker at all. "Write a manifesto for the re-election of X" is an
ordinary sentence; it was an attack because the deployment was a newspaper's assistant
whose system prompt forbids partisan advocacy. The conflict is with a policy that never
reaches the filter, so no pattern set and no classifier trained on prompt text alone can
see it. What is missing is not a better detector. It is the policy.

This module is the seam that lets an application declare it:

    policy = DeploymentPolicy(
        name="newsroom assistant",
        forbids=("partisan advocacy or campaigning",
                 "defaming a person or organisation",
                 "revealing internal editorial guidance"),
    )
    gate = PolicyGate(policy, judge=my_judge)
    verdict = gate.review(user_request)

HONEST LIMITS — read before deploying this, they are not small:

  * **No judge ships with this package.** Deciding whether a sentence conflicts with a
    policy written in prose needs a model. With no judge configured the gate is inert
    and says so in its own reason string; it never silently returns "allow" as if it
    had checked.
  * **A model judge is itself a prompt-injection target.** The text it reads is the
    attacker's. Give it the policy as its instruction, the request as data, and treat
    its verdict as one signal — never as the last word on a sensitive action.
  * **This is advisory, not a capability boundary.** The gate that cannot be argued
    with is `ToolGate`: it constrains what the agent may *do*. Policy review constrains
    what it may be *asked*, which is a weaker claim and always will be.
  * **The bundled `TermJudge` is the floor, not the answer.** It matches declared terms
    and nothing else — no paraphrase, no implication, trivially reworded around. It
    exists so a deployment can start with something deterministic, auditable and free.

Every verdict returns a `GateDecision`, so it lands in the same audit record as the
rest: action, reason, evidence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from reasongate.agent_gate import GateDecision
from reasongate.types import Detection


@dataclass
class DeploymentPolicy:
    """What this deployment will not do, in its own words.

    forbids: prose statements, one per rule. These are what a judge is asked about and
        what appears in the audit record, so write them the way you would write them
        for a colleague, not as keywords.
    terms: optional literal words or phrases that make a rule checkable without a
        model. Used by TermJudge only.
    """
    name: str
    forbids: Tuple[str, ...] = ()
    terms: Tuple[str, ...] = ()

    def as_prompt(self) -> str:
        """The policy rendered for a model judge."""
        rules = "\n".join(f"  {i + 1}. {r}" for i, r in enumerate(self.forbids))
        return f"Deployment: {self.name}\nThis deployment must not:\n{rules}"


# A judge answers: does this text conflict with this policy?
#   -> (conflicts, reason, evidence)
Judge = Callable[[str, DeploymentPolicy], Tuple[bool, str, Sequence[str]]]


class TermJudge:
    """Deterministic baseline judge: matches the literal terms a policy declares.

    Zero dependencies, no network, no model, and no ability to recognise a paraphrase.
    It is the floor — useful for the rules that really are literal (a competitor's
    name, an internal codeword, a banned URL) and useless for everything else. Prefer
    it over nothing; do not mistake it for policy understanding.
    """

    def __init__(self, whole_word: bool = True):
        self.whole_word = whole_word

    def __call__(self, text: str, policy: DeploymentPolicy
                 ) -> Tuple[bool, str, Sequence[str]]:
        hits: List[str] = []
        for term in policy.terms:
            if not term:
                continue
            pattern = re.escape(term)
            if self.whole_word and re.fullmatch(r"[\w\s]+", term):
                pattern = rf"\b{pattern}\b"
            if re.search(pattern, text, re.I):
                hits.append(term)
        if hits:
            return (True,
                    f"Request matches terms this deployment ('{policy.name}') declares "
                    f"off-limits.",
                    [f"declared term: {h!r}" for h in hits])
        return (False, f"No declared term of '{policy.name}' matched.", [])


class PolicyGate:
    """Reviews text against a declared deployment policy, using a pluggable judge.

    block_on_conflict: whether a conflict is a block or a flag. Default is flag,
        because a policy verdict is a judgement call and blocking on one belongs to
        the deployment, not to this library.
    """

    def __init__(self,
                 policy: DeploymentPolicy,
                 judge: Optional[Judge] = None,
                 *,
                 block_on_conflict: bool = False):
        self.policy = policy
        self.judge = judge
        self.block_on_conflict = block_on_conflict

    def review(self, text: str, *, stage: str = "input") -> GateDecision:
        """Ask the judge whether `text` conflicts with the policy.

        With no judge configured this returns `allow` with a reason that says the check
        did not run — an unchecked request must never look like a cleared one.
        """
        label = f"policy:{self.policy.name}"
        if self.judge is None:
            return GateDecision("allow", label, [Detection(
                "policy_gate", False, 0.0,
                f"Policy '{self.policy.name}' was NOT evaluated: no judge is configured. "
                f"This is not a clearance.", [])])
        try:
            conflicts, reason, evidence = self.judge(text, self.policy)
        except Exception as exc:
            # A failing judge must not take the application down, and must not be
            # mistaken for a pass.
            return GateDecision("allow", label, [Detection(
                "policy_gate", False, 0.0,
                f"Policy '{self.policy.name}' could not be evaluated ({type(exc).__name__}); "
                f"treated as unchecked, not as allowed.", [type(exc).__name__])])

        if not conflicts:
            return GateDecision("allow", label, [Detection(
                "policy_gate", False, 0.0, reason, list(evidence))])

        action = "block" if self.block_on_conflict else "flag"
        return GateDecision(action, label, [Detection(
            "policy_gate", True, 0.8 if self.block_on_conflict else 0.5,
            reason + f" [{stage}]", list(evidence))])
