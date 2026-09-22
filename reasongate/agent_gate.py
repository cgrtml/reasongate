"""Provenance-aware tool-call gate: an *action* firewall for agents.

The rule and ML detectors answer "is this text an injection?", a question you
can lose by rewording the attack. This layer answers a different, phrasing-
independent question:

    "May this ACTION proceed, given the trust of the data that produced it?"

It operationalizes the capability-based defense against *indirect* prompt
injection: it breaks the "lethal trifecta" of (untrusted content) + (a sensitive
capability) + (a way out). Even a novel, never-before-seen injection cannot make
an agent wire funds or exfiltrate a record if the sensitive tool is gated whenever
its call originates from untrusted content.

Two independent, explainable signals, strongest first:

  1. Argument taint: a sensitive call whose destination argument (recipient,
     account, URL) *appears in* untrusted content. This is phrasing-independent:
     reword the injection however you like, the exfiltration target still comes
     from the attacker-controlled data, so the action is blocked.
  2. Capability co-presence: a sensitive call made while untrusted content is in
     scope and no trusted authorization was given. The coarse backstop when the
     destination is not literally quoted from the untrusted text.

ADDITIVE + OPT-IN. Nothing here runs unless you declare tool policies and call the
gate. The core Shield and its detectors are untouched; importing this module has no
effect on existing behavior.

HONEST CONTRACT. This is capability-based defense, not magic: the integrating
application must (a) declare which tools are sensitive and which of their arguments
are destinations, and (b) pass the provenance of the data the agent saw (as
`Segment`s with a `trust` field). In return it gets a guarantee the detectors alone
cannot give: untrusted data cannot escalate into a gated action, regardless of how
the injection is worded.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from reasongate.types import Detection, Segment


_WORD_RE = re.compile(r"[^\W_]+", re.UNICODE)


def _norm(s: str) -> str:
    """Casefold + collapse whitespace, so taint matching is not defeated by
    trivial spacing/case differences between the argument and the source text."""
    return " ".join(str(s).casefold().split())


# Minimum length for a destination value to be matched as a substring. Shorter
# values (e.g. a 3-digit code) are matched only as a whole whitespace-delimited
# token, to avoid spurious taint from an incidental digit run.
_MIN_SUBSTR_LEN = 4


def _alnum(s: str) -> str:
    """Keep only alphanumerics, casefolded. Catches a destination that was split or
    punctuated inside the untrusted text ("9 9 8 1", "99-81", "9.9.8.1"), the cheap,
    linear half of what the normalization detector does for prose."""
    return "".join(ch for ch in str(s).casefold() if ch.isalnum())


def _b64_payloads(text: str) -> List[str]:
    """Decoded base64 runs inside the text, so an encoded destination still matches.
    Reuses the core's decoder rather than a second implementation of it."""
    try:
        from reasongate.detectors.normalize import _decode_b64
        return _decode_b64(text)
    except Exception:
        return []


# Argument names that carry content the model composed: what a message says, not where it
# goes. Used when a policy declares no content_args of its own.
_CONTENT_ARG_NAMES = ("body", "content", "message", "text", "subject", "title", "description",
                      "note", "notes", "comment", "summary", "html", "markdown")

# The tokens inside composed content that are worth tracing: addresses and identifiers,
# not prose. A URL, an email, or a long run with digits (an account, a passport number).
_CONTENT_TOKEN = re.compile(
    r"(?:https?://|www\.)\S+"
    r"|\b[\w.+-]+@[\w-]+\.[\w.-]+"
    r"|\b(?=[A-Za-z0-9-]*\d)[A-Za-z0-9][A-Za-z0-9-]{7,}\b"
    r"|\b[\w-]+\.(?:com|org|net|io|co|ai|edu|gov|info|biz|dev|app|tld)(?:/\S*)?", re.I)


def _content_tokens(value: object) -> List[str]:
    """URLs, emails and identifiers inside composed content, as strings."""
    out: List[str] = []
    for scalar in _scalars(value):
        for m in _CONTENT_TOKEN.finditer(scalar):
            tok = m.group(0).rstrip(".,;:)!?\"'")
            if len(tok) >= _MIN_SUBSTR_LEN:
                out.append(tok)
    return out


def _scalars(value: object) -> List[str]:
    """Every scalar inside an argument value, as strings: a list of recipients, a
    dict of fields, or the value itself."""
    if isinstance(value, dict):
        out: List[str] = []
        for v in value.values():
            out.extend(_scalars(v))
        return out
    if isinstance(value, (list, tuple, set)):
        out = []
        for v in value:
            out.extend(_scalars(v))
        return out
    return [str(value)]


_URL_NOISE = re.compile(r"https?://|\bwww\.", re.I)
_URL_MARK = re.compile(r"https?://|\bwww\.|[a-z0-9.-]+\.[a-z]{2,}/", re.I)   # a value shaped like a URL


def _url_key(s: str) -> str:
    """A URL without the parts an attacker or a model varies for free: scheme, a leading
    www., a trailing slash, case. "https://www.X.com/a/" and "x.com/a" become the same key."""
    k = _URL_NOISE.sub("", _norm(s)).strip().rstrip("/")
    return k


def _url_host(s: str) -> str:
    """The host of a URL-shaped value, or "" if it does not look like one. The path is
    what an attacker varies for free once the host is fixed: a destination written as
    "evil.com/x/index.html" reaches the same server as the "evil.com/x" in the injected
    text, so the host is what a destination check has to compare. Measured: without this,
    appending one path segment took AgentDojo attack success from 3.1% to 6.2%."""
    raw = _norm(s)
    if not _URL_MARK.search(raw):
        return ""                      # a bare host or a filename: the literal check has it
    k = _url_key(raw)
    host = k.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    return host if "." in host and not host.endswith(".") and "@" not in host else ""


class _Text:
    """One segment's text with its derived forms computed once and reused.

    authorize() checks every destination scalar and every content token against every
    segment. Recomputing the alphanumeric, URL-stripped and base64-decoded views of a
    2 KB document per token made a six-token message cost 1.2 ms; computed once per
    segment per call it is back under 0.05 ms. Decision-identical by construction.
    """
    __slots__ = ("raw", "_norm", "_tokens", "_alnum", "_urls", "_b64")

    def __init__(self, raw: str):
        self.raw = raw
        self._norm = None
        self._tokens = None
        self._alnum = None
        self._urls = None
        self._b64 = None

    @property
    def norm(self) -> str:
        if self._norm is None:
            self._norm = _norm(self.raw)
        return self._norm

    @property
    def tokens(self) -> set:
        # Whitespace tokens plus word tokens split on punctuation, so a short value such
        # as an id "13" is found when the text says '13', (13), id=13 or 13, but not
        # inside 2134. Short values are matched only as whole tokens (see below);
        # this decides what counts as a token.
        if self._tokens is None:
            self._tokens = set(self.norm.split()) | set(_WORD_RE.findall(self.norm))
        return self._tokens

    @property
    def alnum(self) -> str:
        if self._alnum is None:
            self._alnum = _alnum(self.raw)
        return self._alnum

    @property
    def urls(self) -> str:
        if self._urls is None:
            self._urls = _URL_NOISE.sub("", self.norm)
        return self._urls

    @property
    def b64(self) -> List[str]:
        if self._b64 is None:
            self._b64 = [_norm(d) for d in _b64_payloads(self.raw)]
        return self._b64


def _value_in_untrusted(value: str, text: Union[str, "_Text"]) -> bool:
    prepared = text if isinstance(text, _Text) else _Text(text)
    v = _norm(value)
    if not v:
        return False
    if len(v) >= _MIN_SUBSTR_LEN:
        if v in prepared.norm:
            return True
    elif v in prepared.tokens:
        return True

    # Canonical URL: the destination survived the literal check only because of the
    # scheme, a www., or a trailing slash.
    vk = _url_key(v)
    if len(vk) >= _MIN_SUBSTR_LEN and ("." in vk or "/" in vk) and vk in prepared.urls:
        return True

    # ... or only because of the path. A URL whose HOST is named in untrusted content is
    # a channel to that host whatever comes after the slash, so the host is compared on
    # its own. This is deliberately one-sided: it can over-gate a legitimate page on a
    # host an untrusted document happens to mention, which is the trade a destination
    # check makes, and the utility cost of it is measured in RESULTS.md.
    vh = _url_host(v)
    if len(vh) >= _MIN_SUBSTR_LEN and vh in prepared.urls:
        return True

    # The value survived the literal check. Two cheap transforms an attacker gets
    # for free; both are linear in the text, unlike a full normalization pass.
    va = _alnum(value)
    if len(va) >= _MIN_SUBSTR_LEN and va in prepared.alnum:
        return True
    if len(v) >= _MIN_SUBSTR_LEN:
        for d in prepared.b64:
            if v in d:
                return True
    return False


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
    returns_untrusted: the tool brings outside data in (web fetch, file read, inbox,
        database of user-supplied records). Its result is untrusted for every later
        call in the same GateSession, which is how taint survives more than one hop.
    content_args: arguments that carry what the action SAYS rather than where it goes
        (body, subject, description). A URL, email or identifier inside them that was
        copied from untrusted content, and not named by the principal, taints the
        call: a phishing link in a message to a legitimate recipient, a passport number
        mailed to the user's own wife. Prose overlap is not traced; copying text is what
        agents are for. Empty => inferred from argument names (body, content, subject…).
    """
    name: str
    sensitive: bool = False
    destination_args: Tuple[str, ...] = ()
    requires_authorization: bool = False
    returns_untrusted: bool = False
    content_args: Tuple[str, ...] = ()


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
        # The actual verdict, not a two-way collapse: a policy review can return
        # "flag", and printing that as ALLOW would misreport it.
        head = str(self.action).upper()
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

        # Untrusted sources in scope (a Segment is untrusted unless trust=="trusted";
        # a plain string carries no provenance, so treat it as untrusted). Trusted
        # segments are kept too: a value the principal wrote themselves is theirs.
        untrusted: List[Segment] = []
        trusted: List[Segment] = []
        for seg in context:
            if isinstance(seg, Segment):
                if seg.trust == "trusted":
                    trusted.append(seg)
                elif seg.trust == "neutral":
                    continue          # a clean lookup's result: neither taints nor designates
                else:
                    untrusted.append(seg)
            elif isinstance(seg, str):
                untrusted.append(Segment(text=seg, source="unknown", trust="untrusted"))
        # Derived views of each segment, computed once for every value checked below.
        prepared = {id(seg): _Text(seg.text) for seg in (*trusted, *untrusted)}

        # 1) Argument taint: a destination value quoted from untrusted content.
        # With no destinations declared, every argument is one, content fields included.
        # That is the paranoid dial: an unreviewed policy checks a title quoted verbatim
        # from untrusted text as a destination (it catches AgentDojo's calendar-title
        # payload) and, as the price, blocks a body the user asked to copy from an email
        # (two tasks in the same benchmark). Declaring destination_args is the review
        # that resolves it either way; content is then traced by token only.
        fields = policy.destination_args or tuple(args.keys())
        tainted: List[str] = []
        designated: List[str] = []
        for fname in fields:
            value = args.get(fname)
            if value is None:
                continue
            # A destination is often a list ("recipients": [...]) or a mapping; each
            # scalar inside it is a destination of its own. Stringifying the container
            # would compare "['a@b']" against the text and never match.
            for scalar in _scalars(value):
                # Trusted provenance dominates. If the principal named this value
                # themselves ("refund GB29...", "share it with john@..."), it is theirs
                # even when an untrusted document also contains it; an attacker cannot
                # write into the principal's own request. Measured on AgentDojo, this
                # was 11 of the 34 legitimate tasks the gate used to break.
                if any(_value_in_untrusted(scalar, prepared[id(seg)]) for seg in trusted):
                    designated.append(f"{fname}={scalar!r} named in trusted context")
                    continue
                hit = False
                for seg in untrusted:
                    if _value_in_untrusted(scalar, prepared[id(seg)]):
                        origin = seg.source + (f":{seg.domain}" if seg.domain else "")
                        tainted.append(f"{fname}={scalar!r} originates from untrusted {origin}")
                        hit = True
                        break
                if hit:
                    break
        # 1b) Content taint: a traceable token (URL, email, identifier) inside what the
        #     action says, copied from untrusted content and not named by the principal.
        #     Measured on AgentDojo: every attack the destination check let through after
        #     step 1 was exactly this: the recipient was the user's, the payload was not.
        content_fields = policy.content_args or tuple(
            a for a in args if str(a).lower() in _CONTENT_ARG_NAMES)
        for fname in content_fields:
            value = args.get(fname)
            if value is None or fname in fields and fname in policy.destination_args:
                continue
            for tok in _content_tokens(value):
                if any(_value_in_untrusted(tok, prepared[id(seg)]) for seg in trusted):
                    continue
                for seg in untrusted:
                    if _value_in_untrusted(tok, prepared[id(seg)]):
                        origin = seg.source + (f":{seg.domain}" if seg.domain else "")
                        tainted.append(f"{fname} contains {tok!r} copied from untrusted {origin}")
                        break
                else:
                    continue
                break

        if tainted:
            # Deliberately checked BEFORE the authorization short-circuit: a trusted
            # principal authorizes an ACTION ("email the summary to my manager"), not
            # the argument values an injection may have chosen for it. Authorization
            # does not launder a tainted destination.
            extra = " Authorization covers the action, not attacker-chosen arguments." if authorized else ""
            return GateDecision("block", name, [Detection(
                "tool_gate", True, 0.95,
                f"Sensitive tool '{name}' called with a destination taken from untrusted "
                f"content: tainted action, blocked regardless of wording.{extra}", tainted)])

        if authorized:
            return GateDecision("allow", name, [Detection(
                "tool_gate", False, 0.0,
                f"Sensitive tool '{name}' explicitly authorized by the trusted principal; "
                f"no argument traced to untrusted content.", designated)])

        # 2) Capability co-presence: sensitive action while untrusted content is in
        #    scope and nothing authorized it (breaks the lethal trifecta).
        if untrusted:
            ev = [f"untrusted {s.source}" + (f":{s.domain}" if s.domain else "")
                  for s in untrusted]
            return GateDecision("block", name, [Detection(
                "tool_gate", True, 0.85,
                f"Sensitive tool '{name}' invoked while untrusted content is in scope "
                f"and no trusted authorization was given.", ev)])

        # 3) Sensitive, no untrusted content: allow unless authorization is required.
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


class GateSession:
    """One agent run, with taint carried across tool calls.

    `ToolGate` decides a single call against a fixed context. That is single-hop: it
    catches "the account number is quoted from the poisoned document" and misses "the
    agent fetched a page, the page named the account, and the transfer used *that*".
    The second shape is the realistic one; untrusted data usually reaches a sensitive
    argument through an intermediate tool result.

    A session closes that by treating tool results as context with inherited trust:

      * a tool declared `returns_untrusted=True` (web fetch, file read, inbox, a table
        of user-supplied records) always produces an untrusted result;
      * any other tool produces an untrusted result if untrusted content was in scope
        when it ran, the conservative direction, since the model could have copied
        anything it had read into what it passed on;
      * otherwise the result is trusted and costs nothing later.

    `propagation="arguments"` replaces the second rule with a narrower one: a tool's
    result is untrusted only if the tool is declared `returns_untrusted` or one of its
    argument values was itself quoted from untrusted content (and not named in trusted
    context). Otherwise the result is *neutral*: a directory lookup with no arguments, or
    with the user's own query, neither taints later calls nor vouches for a value the
    injection also names (trusted dominance is for the principal's own words), even after
    the agent has read something poisoned; a lookup whose query came from the poisoned
    text yields an untrusted result. The price is the case the scope rule covers and this
    one cannot: the model choosing, on the injection's instruction, among entries of a
    listing the attacker did not write. Measured on AgentDojo in RESULTS.md.

    Usage mirrors the agent loop itself:

        session = GateSession(gate, context=[user_request])
        decision = session.authorize(call)
        if decision.allowed:
            session.record_result(call, run_tool(call))

    Same contract as the gate: additive, opt-in, and it never raises into the caller.
    A session that is never given results behaves exactly like the plain gate.
    """

    def __init__(self,
                 gate: ToolGate,
                 context: Optional[Iterable[Union[Segment, str]]] = None,
                 *,
                 propagation: str = "scope"):
        if propagation not in ("scope", "arguments"):
            raise ValueError("propagation must be 'scope' or 'arguments'")
        self.gate = gate
        self.propagation = propagation
        self.context: List[Segment] = []
        for seg in context or []:
            self.context.append(seg if isinstance(seg, Segment)
                                else Segment(text=str(seg), source="unknown",
                                             trust="untrusted"))

    # -- context -----------------------------------------------------------

    def add_context(self, segment: Union[Segment, str], *, trust: str = "untrusted",
                    source: str = "unknown") -> Segment:
        """Add data the agent saw. Plain strings are treated as untrusted."""
        seg = segment if isinstance(segment, Segment) else Segment(
            text=str(segment), source=source, trust=trust)
        self.context.append(seg)
        return seg

    def _untrusted_in_scope(self) -> bool:
        return any(s.trust not in ("trusted", "neutral") for s in self.context)

    def _arguments_tainted(self, call: ToolCall) -> bool:
        """Does any argument value of this call trace to untrusted context?"""
        args = call.get("args") if isinstance(call, dict) else None
        if not isinstance(args, dict) or not args:
            return False
        trusted = [s for s in self.context if s.trust == "trusted"]
        untrusted = [s for s in self.context if s.trust not in ("trusted", "neutral")]
        if not untrusted:
            return False
        prepared = {id(seg): _Text(seg.text) for seg in (*trusted, *untrusted)}
        for value in args.values():
            for scalar in _scalars(value):
                if any(_value_in_untrusted(scalar, prepared[id(seg)]) for seg in trusted):
                    continue
                if any(_value_in_untrusted(scalar, prepared[id(seg)]) for seg in untrusted):
                    return True
        return False

    # -- the loop ----------------------------------------------------------

    def authorize(self, call: ToolCall, *, authorized: bool = False) -> GateDecision:
        """Authorize one call against everything the agent has seen so far."""
        return self.gate.authorize(call, context=self.context, authorized=authorized)

    def record_result(self,
                      call: ToolCall,
                      result: object,
                      *,
                      trust: Optional[str] = None) -> Segment:
        """Feed a tool's result back in, with its trust inherited from the run so far.

        `trust` overrides the inference when the integrator knows better (a result it
        has itself validated, or one it wants treated as untrusted regardless).
        """
        name = str(call.get("name", "")) if isinstance(call, dict) else str(call)
        try:
            policy = self.gate._policy_for(name)
            if trust is None:
                if policy.returns_untrusted:
                    trust = "untrusted"
                elif self.propagation == "arguments":
                    # A clean lookup's result is neutral, not trusted: it must not
                    # designate a value the injection also names (trusted dominance is
                    # for the principal's own words), and it must not taint either.
                    trust = "untrusted" if self._arguments_tainted(call) else "neutral"
                elif self._untrusted_in_scope():
                    trust = "untrusted"
                else:
                    trust = "trusted"
            seg = Segment(text=_result_text(result), source=f"tool:{name}",
                          trust=trust, domain=None)
            self.context.append(seg)
            return seg
        except Exception:
            # A session must not break the agent either: fall back to the safe side.
            seg = Segment(text=_result_text(result), source=f"tool:{name}",
                          trust="untrusted", domain=None)
            self.context.append(seg)
            return seg


def _result_text(result: object) -> str:
    """Flatten a tool result to the text the gate can match a destination against."""
    if isinstance(result, str):
        return result
    if isinstance(result, (list, tuple)):
        return "\n".join(_result_text(r) for r in result)
    if isinstance(result, dict):
        return "\n".join(f"{k}: {_result_text(v)}" for k, v in result.items())
    return str(result)
