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
_WORD_SPLIT = re.compile(r"[\s,;<>()\[\]\"']+")


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

# Content taint applies to tools whose effect leaves the local trust boundary: a message,
# a post, an upload. A local write is different. Copying a colleague's address out of one
# file into another inside the directory the server already grants is not a channel out,
# and tracing it costs a question with no security behind it (measured on the real
# filesystem server in `eval/mcp_friction.py`: two of twelve ordinary tasks, both of them
# this shape). The destination check is unaffected, so a path or an identifier an
# injection chose is still blocked on a local tool.
_OUTBOUND_EFFECT_RE = re.compile(
    r"(?:^|[^a-z])(?:send|post|publish|share|upload|email|mail|message|dm|notify|invite|"
    r"tweet|broadcast|submit|webhook|comment|reply|forward|transfer|pay|webpage|web page|"
    r"browse|browser|visit|fetch|download|http|curl|wget|navigate)(?:[^a-z]|$)", re.I)


def _sends_outbound(name: str) -> bool:
    """Does this tool's effect carry data outside the local trust boundary?"""
    return bool(_OUTBOUND_EFFECT_RE.search(re.sub(r"[_\-./]+", " ", str(name))))

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


_PATHY = re.compile(r"[/\\]")
_ADDR = re.compile(r"^([^@\s]+)@([^@\s]+)$")


def _address_key(value: str) -> str:
    """An address with the part a mail system ignores removed.

    `user+anything@example.com` is delivered to `user@example.com` on most providers, so
    an injection that names the plain address and a call that adds a tag are the same
    destination. Found by an attacker with the gate's answers in front of it
    (`eval/adaptive_mcp.py`). The dot trick in Gmail local parts is deliberately not
    normalised: it is one provider's rule, and applying it everywhere would match two
    addresses that really are different on most others. Returns "" for anything that is
    not address shaped.
    """
    m = _ADDR.match(_norm(value))
    if not m:
        return ""
    local, domain = m.group(1), m.group(2).rstrip(".")
    return f"{local.split('+', 1)[0]}@{domain}"


def _path_key(value: str) -> str:
    """A path with the segments a filesystem resolves away already resolved.

    A server given "notes/sub/../backup.txt" writes "notes/backup.txt", and it does not
    need "sub" to exist: it normalises first. A destination check that compares the string
    it was handed therefore misses a dictated path written with one dot-dot segment, which
    is a bypass with a real effect on disk (measured in `eval/adaptive_mcp.py`). Returns ""
    for a value that is not path shaped, so nothing else pays for this.
    """
    if not _PATHY.search(value):
        return ""
    raw = value.replace("\\", "/")
    lead = "/" if raw.startswith("/") else ""
    out: List[str] = []
    for seg in raw.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out and out[-1] != "..":
                out.pop()
            elif not lead:
                out.append("..")
            continue
        out.append(seg)
    return _norm(lead + "/".join(out))


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
    __slots__ = ("raw", "_norm", "_tokens", "_alnum", "_urls", "_b64", "_paths", "_addrs")

    def __init__(self, raw: str):
        self.raw = raw
        self._norm = None
        self._tokens = None
        self._alnum = None
        self._urls = None
        self._b64 = None
        self._paths = None
        self._addrs = None

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
    def addresses(self) -> str:
        if self._addrs is None:
            self._addrs = " ".join(
                _address_key(tok) or tok for tok in _WORD_SPLIT.split(self.norm) if tok)
        return self._addrs

    @property
    def paths(self) -> str:
        if self._paths is None:
            self._paths = " ".join(
                _path_key(tok) or tok for tok in self.norm.split())
        return self._paths

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


_STOPWORDS = frozenset("""
the and for with from that this into your their there here what when where which will
shall should would could please thank thanks kindly about above after again against
between before being been have has had does did doing then than them they were was
are you our not all any can may must need send make move take give find show tell
new old one two get set use its it's a an of to in on at by is be as or if so we me my
""".split())


def _distinctive(text: str) -> set:
    """The words in a request that could identify one record rather than any record."""
    return {t for t in _WORD_RE.findall(_norm(text))
            if len(t) >= 4 and t not in _STOPWORDS and not t.isdigit()}


def _record_around(text: str, value: str) -> str:
    """The line of a tool result that carried this value. A listing puts one record per
    line, which is what makes this a record rather than a window, so the line breaks have
    to survive: the usual normalisation collapses them and would turn a whole listing into
    one record, which matches everything and designates everything."""
    target = _norm(value)
    if not target:
        return ""
    for line in str(text).splitlines():
        flat = _norm(line)
        if target in flat or (_path_key(target) and _path_key(target) in flat) or (
                _address_key(target) and _address_key(target) in flat):
            return flat
    return ""


def _vouched(value: str, entry: str) -> bool:
    """Does this destination match an allowed entry? An entry beginning with "@" or "."
    covers a whole domain or suffix; anything else is compared whole, after the same
    canonicalisation the taint check uses, so an allowed address cannot be evaded by a
    mail tag or a path written with dot segments."""
    v, e = _norm(value), _norm(entry)
    if not v or not e:
        return False
    if e.startswith(("@", ".", "/")):
        return v.endswith(e) or _address_key(v).endswith(e) or _path_key(v).startswith(e)
    return v == e or _address_key(v) == _address_key(e) or (
        bool(_path_key(v)) and _path_key(v) == _path_key(e))


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

    # ... or only because of a segment a filesystem resolves away. Both sides are
    # normalised, because the dot segments can be on either one.
    vp = _path_key(value)
    if len(vp) >= _MIN_SUBSTR_LEN and (vp in prepared.norm or vp in prepared.paths):
        return True

    # ... or only because of a tag a mail system ignores.
    va = _address_key(value)
    if len(va) >= _MIN_SUBSTR_LEN and (va in prepared.norm or va in prepared.addresses):
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
    allowed_destinations: destination values a deployment vouches for outright (the
        user's own address, an internal domain, a directory the attacker cannot write to).
        Only consulted when the gate is asked for vouched destinations; a suffix match, so
        "@northwind.example" covers every address in that domain.
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
    allowed_destinations: Tuple[str, ...] = ()


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
                 fail_closed: bool = True,
                 vouched_destinations: bool = False,
                 allowed_destinations: Iterable[str] = (),
                 designate_by_record: bool = False):
        # designate_by_record is an experiment with a published negative result; see below.
        if isinstance(policies, dict):
            self.policies = dict(policies)
        else:
            self.policies = {p.name: p for p in (policies or [])}
        self.default_sensitive = default_sensitive
        self.fail_closed = fail_closed
        # Two ways to be wrong about a destination, and until now only one of them was
        # checked. Taint answers "did this value come out of untrusted content", which
        # assumes the attacker's destination appears in that content verbatim. It need not.
        # An injection that *describes* the address, or spells it out, or points at a
        # signature block, leaves the model to write the canonical form, and the canonical
        # form appears nowhere: nothing to trace, nothing to block. Measured on six
        # description styles, four walked through.
        #
        # `vouched_destinations` asks the other question: is this value justified? A
        # destination must be one the principal named or one the deployment vouched for,
        # and a value that appears nowhere does not run. That turns the open set of things
        # an attacker might say into a closed set of places an action may go, which is the
        # only answer to a described destination that does not depend on reading the
        # description. Its cost is in RESULTS.md, and it is not small.
        self.vouched_destinations = vouched_destinations
        self.allowed_destinations = tuple(allowed_destinations)
        # MEASURED AND REJECTED. Keep this off. People name things by description rather
        # than by value ("move the product sync"), the agent turns the description into an
        # identifier by looking it up, and taint then stops the work the principal asked
        # for. The tempting repair is to look at the record the value came out of: if the
        # line that carried it also carries the principal's own words, treat it as
        # designated. On AgentDojo that recovers five user tasks and takes attack success
        # from 3.1% to 15.3%, because an injection lives inside the very document the user
        # asked about, so the attacker's record carries the user's words too. It is kept
        # here, off, and deliberately not exposed by the gateway, so the negative result
        # stays reproducible without being reachable by accident.
        self.designate_by_record = designate_by_record

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
        allow_list = tuple(policy.allowed_destinations) + self.allowed_destinations
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
                # A destination the deployment vouched for is safe wherever the agent read
                # it. Saying "our own domain is fine" and then blocking a reply to a
                # colleague because their address arrived in an email is not a security
                # property, it is a bug: the attacker gains nothing by naming a place the
                # deployment already controls. Measured on the mail tasks, this is half
                # the friction that mode otherwise costs.
                if any(_vouched(scalar, entry) for entry in allow_list):
                    designated.append(f"{fname}={scalar!r} is an allowed destination")
                    continue
                hit = False
                for seg in untrusted:
                    if _value_in_untrusted(scalar, prepared[id(seg)]):
                        origin = seg.source + (f":{seg.domain}" if seg.domain else "")
                        if self.designate_by_record and trusted:
                            record = _record_around(seg.text, scalar)
                            asked = set().union(*(_distinctive(t.text) for t in trusted))
                            shared = asked & _distinctive(record)
                            if len(shared) >= 2:
                                designated.append(
                                    f"{fname}={scalar!r} identifies the record the principal "
                                    f"described ({', '.join(sorted(shared)[:3])})")
                                break
                        tainted.append(f"{fname}={scalar!r} originates from untrusted {origin}")
                        hit = True
                        break
                if hit:
                    break
        # 1b) Content taint: a traceable token (URL, email, identifier) inside what the
        #     action says, copied from untrusted content and not named by the principal.
        #     Measured on AgentDojo: every attack the destination check let through after
        #     step 1 was exactly this: the recipient was the user's, the payload was not.
        # A declared content_args list is honoured as written; when nothing is declared,
        # the arguments are inferred, and only for a tool that sends data outward.
        content_fields = policy.content_args or (
            tuple(a for a in args if str(a).lower() in _CONTENT_ARG_NAMES)
            if _sends_outbound(name) else ())
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
            # Say which of the two findings it was. The same sentence used to report
            # "destination" for both, which is wrong in the case a person is most likely
            # to see: a value copied into what the action says, not into where it goes.
            where = ("a destination taken from untrusted content"
                     if any(" originates from untrusted " in t for t in tainted)
                     else "a value copied from untrusted content into what it says")
            return GateDecision("block", name, [Detection(
                "tool_gate", True, 0.95,
                f"Sensitive tool '{name}' called with {where}: tainted action, blocked "
                f"regardless of wording.{extra}", tainted)])

        if self.vouched_destinations:
            unvouched: List[str] = []
            for fname in fields:
                value = args.get(fname)
                if value is None:
                    continue
                for scalar in _scalars(value):
                    if not scalar:
                        continue
                    if any(_value_in_untrusted(scalar, prepared[id(seg)]) for seg in trusted):
                        continue
                    if any(_vouched(scalar, entry) for entry in allow_list):
                        continue
                    unvouched.append(f"{fname}={scalar!r} is in neither the principal's "
                                     f"request nor the allowed destinations")
            if unvouched:
                return GateDecision("block", name, [Detection(
                    "tool_gate", True, 0.9,
                    f"Sensitive tool '{name}' called with a destination nothing vouches for. "
                    f"A value that appears nowhere the agent was told to look cannot be "
                    f"traced, so it is refused rather than allowed by default.", unvouched)])

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

    def trace(self,
              call: ToolCall,
              context: Iterable[Union[Segment, str]] = ()) -> Dict[str, List[str]]:
        """Where every argument value of this call came from, without deciding anything.

        The gate answers one question at a time, and only about sensitive tools. This
        answers a different one, about any tool: for each argument, is the value
        something the principal wrote, something a tool result contained, or something
        that appears nowhere the agent has seen? It changes no state and takes no
        decision; it exists because "why did the agent use *that* value" is a question
        an integrator asks far more often than "should this be blocked", and the gate
        already has the provenance to answer it.

        Returns argument name to a list of origins, most trusted first:
        ``["named by the principal"]``, ``["from tool:read_file"]``, or ``["not seen in
        anything the agent read"]``.
        """
        name = str(call.get("name", "")) if isinstance(call, dict) else str(call)
        args = dict(call.get("args") or {}) if isinstance(call, dict) else {}
        trusted, untrusted = [], []
        for seg in context:
            if isinstance(seg, Segment):
                if seg.trust == "trusted":
                    trusted.append(seg)
                elif seg.trust != "neutral":
                    untrusted.append(seg)
            elif isinstance(seg, str):
                untrusted.append(Segment(text=seg, source="unknown", trust="untrusted"))
        prepared = {id(seg): _Text(seg.text) for seg in (*trusted, *untrusted)}
        out: Dict[str, List[str]] = {}
        for fname, value in args.items():
            origins: List[str] = []
            for scalar in _scalars(value):
                if not scalar:
                    continue
                if any(_value_in_untrusted(scalar, prepared[id(seg)]) for seg in trusted):
                    origins.append("named by the principal")
                    continue
                hit = None
                for seg in untrusted:
                    if _value_in_untrusted(scalar, prepared[id(seg)]):
                        hit = seg.source + (f":{seg.domain}" if seg.domain else "")
                        break
                origins.append(f"from {hit}" if hit else "not seen in anything the agent read")
            # Same origin repeated for every scalar of a list argument is noise.
            seen, uniq = set(), []
            for o in origins:
                if o not in seen:
                    seen.add(o)
                    uniq.append(o)
            if uniq:
                out[fname] = uniq
        return out

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

    def trace(self, call: ToolCall) -> Dict[str, List[str]]:
        """`ToolGate.trace` against everything this session has seen so far."""
        return self.gate.trace(call, context=self.context)

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
