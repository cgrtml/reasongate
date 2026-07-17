"""Provenance-aware tool-call gate — an *action* firewall for agents.

The rule and ML detectors answer "is this text an injection?" — a question you
can lose by rewording the attack. This layer answers a different, phrasing-
independent question:

    "May this ACTION proceed, given the trust of the data that produced it?"

It operationalizes the capability-based defense against *indirect* prompt
injection — breaking the "lethal trifecta" of (untrusted content) + (a sensitive
capability) + (a way out). Even a novel, never-before-seen injection cannot make
an agent wire funds or exfiltrate a record if the sensitive tool is gated whenever
its call originates from untrusted content.

Two independent, explainable signals, strongest first:

  1. Argument taint — a sensitive call whose destination argument (recipient,
     account, URL) *appears in* untrusted content. This is phrasing-independent:
     reword the injection however you like, the exfiltration target still comes
     from the attacker-controlled data, so the action is blocked.
  2. Capability co-presence — a sensitive call made while untrusted content is in
     scope and no trusted authorization was given. The coarse backstop when the
     destination is not literally quoted from the untrusted text.

ADDITIVE + OPT-IN. Nothing here runs unless you declare tool policies and call the
gate. The core Shield and its detectors are untouched; importing this module has no
effect on existing behavior.

HONEST CONTRACT. This is capability-based defense, not magic: the integrating
application must (a) declare which tools are sensitive and which of their arguments
are destinations, and (b) pass the provenance of the data the agent saw (as
`Segment`s with a `trust` field). In return it gets a guarantee the detectors alone
cannot give — untrusted data cannot escalate into a gated action, regardless of how
the injection is worded.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from reasongate.types import Detection, Segment


def _norm(s: str) -> str:
    """Casefold + collapse whitespace, so taint matching is not defeated by
    trivial spacing/case differences between the argument and the source text."""
    return " ".join(str(s).casefold().split())


# Minimum length for a destination value to be matched as a substring. Shorter
# values (e.g. a 3-digit code) are matched only as a whole whitespace-delimited
# token, to avoid spurious taint from an incidental digit run.
_MIN_SUBSTR_LEN = 4


def _value_in_untrusted(value: str, text: str) -> bool:
    v = _norm(value)
    if not v:
        return False
    t = _norm(text)
    if len(v) >= _MIN_SUBSTR_LEN:
        return v in t
    return v in t.split()


@dataclass
class ToolPolicy:
    """Declares how a single tool must be gated.

    sensitive: the tool is irreversible / high-authority (transfer, delete,
        external send, code execution). Non-sensitive tools are never gated.
    destination_args: argument names whose *value* must not originate from
        untrusted content (recipient, account, url, path). Empty => every argument
        is checked (safe default for a sensitive tool).
    requires_authorization: a sensitive call must be explicitly authorized by the
        trusted principal even when no untrusted content is in scope.
    """
    name: str
    sensitive: bool = False
    destination_args: Tuple[str, ...] = ()
    requires_authorization: bool = False


@dataclass
class GateDecision:
    action: str                       # "allow" | "block"
    tool: str
    detections: List[Detection] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.action != "block"

    def explain(self) -> str:
        triggered = [d for d in self.detections if d.triggered] or self.detections
        head = "BLOCK" if self.action == "block" else "ALLOW"
        lines = [f"[{head}] tool '{self.tool}'"]
        for d in triggered:
            lines.append(f"  - {d.reason}")
            if d.matches:
                lines.append(f"    evidence: {', '.join(d.matches[:3])}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {"action": self.action, "tool": self.tool,
                "detections": [d.to_dict() for d in self.detections]}


ToolCall = Dict[str, object]          # {"name": str, "args": dict}


class ToolGate:
    """Gates proposed tool calls by the trust of the data that produced them.

    policies: ToolPolicy list/dict. Tools without a policy are treated as
        non-sensitive (allowed) unless `default_sensitive=True`.
    fail_closed: on an unexpected internal error, block *sensitive* tools (safe
        default) rather than letting a broken gate silently allow them. Non-
        sensitive tools always pass. The gate never raises into the caller.
    """

    def __init__(self,
                 policies: Union[Sequence[ToolPolicy], Dict[str, ToolPolicy], None] = None,
                 *,
                 default_sensitive: bool = False,
                 fail_closed: bool = True):
        if isinstance(policies, dict):
            self.policies = dict(policies)
        else:
            self.policies = {p.name: p for p in (policies or [])}
        self.default_sensitive = default_sensitive
        self.fail_closed = fail_closed

    def _policy_for(self, name: str) -> ToolPolicy:
        p = self.policies.get(name)
        if p is not None:
            return p
        return ToolPolicy(name=name, sensitive=self.default_sensitive)

    def authorize(self,
                  call: ToolCall,
                  *,
                  context: Optional[Iterable[Union[Segment, str]]] = None,
                  authorized: bool = False) -> GateDecision:
        """Decide whether a single proposed tool call may execute.

        call: {"name": str, "args": dict}.
        context: the data the agent saw. Segments with trust != "trusted" are
            untrusted; plain strings are treated as untrusted too (conservative).
        authorized: the trusted principal explicitly authorized THIS action.
        """
        name = str(call.get("name", ""))
        try:
            return self._authorize(name, call.get("args") or {},
                                   context or [], authorized)
        except Exception as exc:  # a gate must never break the calling agent
            policy = self._policy_for(name)
            if policy.sensitive and self.fail_closed:
                return GateDecision("block", name, [Detection(
                    "tool_gate", True, 1.0,
                    f"Gate error on sensitive tool '{name}'; failing closed.",
                    [type(exc).__name__])])
            return GateDecision("allow", name, [Detection(
                "tool_gate", False, 0.0,
                f"Gate error on '{name}'; non-sensitive, allowed.",
                [type(exc).__name__])])

    def _authorize(self, name: str, args: dict,
                   context: Iterable[Union[Segment, str]],
                   authorized: bool) -> GateDecision:
        policy = self._policy_for(name)

        if not policy.sensitive:
            return GateDecision("allow", name, [Detection(
                "tool_gate", False, 0.0,
                f"'{name}' is not a sensitive tool; not gated.", [])])

        if authorized:
            return GateDecision("allow", name, [Detection(
                "tool_gate", False, 0.0,
                f"Sensitive tool '{name}' explicitly authorized by the trusted principal.",
                [])])

        # Untrusted sources in scope (a Segment is untrusted unless trust=="trusted";
        # a plain string carries no provenance, so treat it as untrusted).
        untrusted: List[Segment] = []
        for seg in context:
            if isinstance(seg, Segment):
                if seg.trust != "trusted":
                    untrusted.append(seg)
            elif isinstance(seg, str):
                untrusted.append(Segment(text=seg, source="unknown", trust="untrusted"))

        # 1) Argument taint — a destination value quoted from untrusted content.
        fields = policy.destination_args or tuple(args.keys())
        tainted: List[str] = []
        for fname in fields:
            value = args.get(fname)
            if value is None:
                continue
            for seg in untrusted:
                if _value_in_untrusted(str(value), seg.text):
                    origin = seg.source + (f":{seg.domain}" if seg.domain else "")
                    tainted.append(f"{fname}={value!r} originates from untrusted {origin}")
                    break
        if tainted:
            return GateDecision("block", name, [Detection(
                "tool_gate", True, 0.95,
                f"Sensitive tool '{name}' called with a destination taken from untrusted "
                f"content — tainted action, blocked regardless of wording.", tainted)])

        # 2) Capability co-presence — sensitive action while untrusted content is in
        #    scope and nothing authorized it (breaks the lethal trifecta).
        if untrusted:
            ev = [f"untrusted {s.source}" + (f":{s.domain}" if s.domain else "")
                  for s in untrusted]
            return GateDecision("block", name, [Detection(
                "tool_gate", True, 0.85,
                f"Sensitive tool '{name}' invoked while untrusted content is in scope "
                f"and no trusted authorization was given.", ev)])

        # 3) Sensitive, no untrusted content — allow unless authorization is required.
        if policy.requires_authorization:
            return GateDecision("block", name, [Detection(
                "tool_gate", True, 0.70,
                f"Sensitive tool '{name}' requires explicit authorization.", [])])

        return GateDecision("allow", name, [Detection(
            "tool_gate", False, 0.0,
            f"'{name}' allowed: no untrusted origin in scope.", [])])

    def authorize_all(self,
                      calls: Sequence[ToolCall],
                      *,
                      context: Optional[Iterable[Union[Segment, str]]] = None,
                      authorized: bool = False) -> List[GateDecision]:
        ctx = list(context or [])
        return [self.authorize(c, context=ctx, authorized=authorized) for c in calls]
