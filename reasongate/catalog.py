"""A starting catalog of tool policies, inferred from tool names.

The gate's honest weakness is that it only knows what the integrator declares. An
application with forty tools has to classify forty tools before the gate does
anything, and the usual outcome of that is an empty policy list and a gate that
silently allows everything.

This closes the gap between "installed" and "configured", not the gap between
"configured" and "correct". Name inference is a heuristic and the wrong thing to
rely on: a tool called `process_request` that wires money is invisible to it, and
`delete_draft` is flagged as destructive when it is not. Treat the output as a
first draft to review, print it (`describe`) and correct it, and keep the tools
your application actually cares about declared by hand.

    from reasongate import ToolGate
    from reasongate.catalog import infer_policies

    policies = infer_policies(["search_docs", "send_email", "transfer_funds"])
    print(describe(policies))          # review this before shipping it
    gate = ToolGate(policies)
"""
from __future__ import annotations

import re
from typing import Iterable, List, Sequence

from reasongate.agent_gate import ToolPolicy, _CONTENT_ARG_NAMES, _sends_outbound

# Verbs and nouns that mark an irreversible or outward-facing capability: money,
# messages that leave the system, destruction, code execution, publication.
_SENSITIVE = (
    r"send|email|mail|sms|text|message|notify|post|publish|tweet|share|forward|reply|"
    r"transfer|pay|payment|purchase|buy|charge|refund|invoice|wire|withdraw|"
    r"delete|remove|destroy|drop|truncate|purge|revoke|disable|"
    r"exec|execute|run|shell|bash|command|eval|script|deploy|release|merge|push|"
    r"write|create|update|upsert|insert|modify|edit|patch|overwrite|rename|move|copy|upload|chmod|chown|"
    r"grant|invite|add user|add member|add participant|approve|sign|order|book|"
    r"reserve|reservation|schedule|reschedule|cancel|append|call"
)

# Tools that bring outside data in. Their results are untrusted for every later call
# in a GateSession; this is what makes taint survive more than one hop.
_INGEST = (
    r"fetch|read|get|search|browse|crawl|scrape|retrieve|lookup|query|find|list|load|"
    r"download|open|view|inbox|receive|poll|subscribe|history|memory|recall|rag|"
    r"knowledge|document|page|url|web"
)

# Argument names that carry a destination: where the action lands, who receives it.
_DESTINATION_ARGS = (
    "to", "to_account", "recipient", "recipients", "cc", "bcc", "email", "address",
    "account", "account_id", "iban", "wallet", "url", "endpoint", "webhook", "host",
    "path", "file", "filename", "filepath", "destination", "dest", "target",
    "channel", "chat_id", "phone", "number", "repo", "repository", "branch",
    "bucket", "key", "table", "collection", "queue", "topic",
    # principals and credentials: who is affected, what unlocks the account
    "participants", "attendees", "invitees", "members", "member", "user", "users",
    "username", "user_email", "user_id", "password", "new_password", "token",
)


_DESTRUCTIVE_RE = re.compile(r"\b(?:delete|remove|cancel|revoke|destroy|purge|drop|truncate|disable|"
                             r"terminate|wipe|erase)\b", re.I)


def _is_destination_arg(arg: str, tool_words: str = "") -> bool:
    a = str(arg).lower()
    if a in _DESTINATION_ARGS:
        return True
    # "<thing>_id" is where an IRREVERSIBLE action lands (delete_file(file_id),
    # cancel_event(event_id)) and is checked there. For an edit (update, share, append)
    # the id only names the object being worked on, usually looked up from the
    # principal's own store a moment earlier; treating it as a destination blocks
    # ordinary "update the one I just found" flows for no security gain (measured).
    if a == "id" or a.endswith("_id"):
        return bool(_DESTRUCTIVE_RE.search(tool_words))
    return False

# Reads that reach out: a fetch, a browse, a download. They have no effect the gate can
# see, but the address they are given is an exfiltration channel; a query string carries
# data out, and "visit this URL" is a whole class of injection goals. Measured on
# AgentDojo, every attack the taint gate let through on the slack suite was one of these.
# So a read whose destination is a URL is gated on that destination (and only that), and
# its result stays untrusted like any other ingest.
_OUTBOUND_READ = r"webpage|web page|browse|browser|open url|fetch url|visit|download|http|curl|wget|navigate"


_URL_ARGS = ("url", "uri", "link", "href", "endpoint", "address", "webhook", "host")

# Membership changes: "add ... participants", "remove ... members", "invite ... attendees".
# The verb and the noun need not be adjacent ("add_calendar_event_participants").
_MEMBERSHIP_RE = re.compile(r"\b(?:add|remove|invite|assign|revoke)\b.*\b(?:participants?|attendees?|"
                            r"invitees?|members?|users?|guests?|collaborators?)\b", re.I)

_SENSITIVE_RE = re.compile(rf"(?:^|[^a-z])(?:{_SENSITIVE})(?:[^a-z]|$)", re.I)
_OUTBOUND_RE = re.compile(rf"(?:^|[^a-z])(?:{_OUTBOUND_READ})(?:[^a-z]|$)", re.I)
_INGEST_RE = re.compile(rf"(?:^|[^a-z])(?:{_INGEST})(?:[^a-z]|$)", re.I)


def sends_outbound(name: str) -> bool:
    """Does this tool's effect carry data outside the local trust boundary?

    `send_email`, `post_webpage`, `share_file` do; `write_file`, `edit_file`,
    `create_directory` do not. Only the first kind gets content arguments inferred: a
    value copied between two local files is not a channel out. One rule, kept in
    `reasongate.agent_gate` so the draft and the gate's own fallback cannot drift apart.
    """
    return _sends_outbound(name)


def _words(name: str) -> str:
    """snake_case, camelCase and dotted names all become space-separated words."""
    spaced = re.sub(r"[_\-./]+", " ", str(name))
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", spaced)
    return " " + spaced.lower() + " "


def infer_policy(name: str, *, known_args: Sequence[str] = ()) -> ToolPolicy:
    """Draft a policy for one tool from its name (and argument names, when known).

    `known_args` narrows `destination_args` to the arguments the tool really takes;
    without it a sensitive tool has every argument checked, which is the safe default
    and the noisier one.
    """
    words = _words(name)
    ingest = bool(_INGEST_RE.search(words))
    sensitive = bool(_SENSITIVE_RE.search(words)) or bool(_MEMBERSHIP_RE.search(words))
    # A name that LEADS with a read verb is a read tool even if a sensitive noun
    # appears later ("search_contacts_by_email", "get_sent_emails"). Only the
    # leading verb decides; "update_from_url" still counts as both.
    first = words.split()[0] if words.split() else ""
    if sensitive and _INGEST_RE.search(f" {first} ") and not _SENSITIVE_RE.search(f" {first} "):
        sensitive = False
    # A tool that both reads and writes ("update_from_url") is treated as both: its
    # result is untrusted and its own call is gated.
    dests: List[str] = []
    if known_args:
        dests = [a for a in known_args if _is_destination_arg(a, words)]
    # Outbound read: gated on its URL argument only. Declared by name, or by an argument
    # name when the schema is known ("fetch(link=...)").
    url_args = [a for a in known_args if a.lower() in _URL_ARGS] if known_args else []
    if ingest and (_OUTBOUND_RE.search(words) or url_args):
        return ToolPolicy(name=str(name), sensitive=True,
                          destination_args=tuple(url_args), returns_untrusted=True)
    return ToolPolicy(
        name=str(name),
        sensitive=sensitive,
        destination_args=tuple(dests),
        returns_untrusted=ingest,
    )


def infer_policies(names: Iterable[str]) -> List[ToolPolicy]:
    """Draft policies for a list of tool names. Review before shipping."""
    return [infer_policy(n) for n in names]


def describe(policies: Iterable[ToolPolicy]) -> str:
    """A reviewable table of what was inferred: print this, then correct it."""
    rows = ["tool                           sensitive  returns-untrusted  destination args        content args",
            "-" * 104]
    for p in policies:
        dests = (", ".join(p.destination_args) or "(all)") if p.sensitive else ""
        content = ", ".join(getattr(p, "content_args", ()) or ())
        rows.append(f"{p.name:30} {'yes' if p.sensitive else 'no':9}  "
                    f"{'yes' if p.returns_untrusted else 'no':17}  {dests:22}  {content}")
    rows.append("")
    rows.append("Inferred from names. A tool whose name does not say what it does is "
                "invisible here; declare those by hand.")
    return "\n".join(rows)


# ----------------------------------------------------------------------------------------
# From schemas. A tool definition already says what its arguments are called; that is
# enough to draft destination and content arguments without anyone typing them.
# ----------------------------------------------------------------------------------------

def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _arg_names(tool) -> List[str]:
    """Argument names from any of the shapes tools are declared in."""
    # Anthropic: {"name", "input_schema": {"properties": {...}}}
    # OpenAI:    {"type": "function", "function": {"name", "parameters": {"properties"}}}
    # MCP:       {"name", "inputSchema": {"properties": {...}}}
    # pydantic-backed (AgentDojo): .parameters.model_fields
    fn = _get(tool, "function")
    if fn is not None and _get(fn, "name"):
        tool = fn
    for key in ("input_schema", "inputSchema", "parameters"):
        schema = _get(tool, key)
        if schema is None:
            continue
        props = _get(schema, "properties")
        if isinstance(props, dict):
            return list(props.keys())
        fields = _get(schema, "model_fields")
        if isinstance(fields, dict):
            return list(fields.keys())
    return []


def _tool_name(tool) -> str:
    fn = _get(tool, "function")
    if fn is not None and _get(fn, "name"):
        return str(_get(fn, "name"))
    return str(_get(tool, "name", ""))


def policies_from_schemas(tools: Iterable) -> List[ToolPolicy]:
    """Draft a policy per tool from its definition: name plus argument names.

    Sensitivity and ingest come from the name (as in `infer_policy`); destination
    arguments come from the schema's argument names, so a sensitive tool is checked on
    `recipient` rather than on every field; content arguments (body, subject, …) are
    listed explicitly so `describe()` shows what content taint will read. The same
    caveat as everything in this module: a draft to review, printed by `describe`, not
    a configuration to trust unread.
    """
    out: List[ToolPolicy] = []
    for tool in tools:
        name = _tool_name(tool)
        if not name:
            continue
        args = _arg_names(tool)
        p = infer_policy(name, known_args=args)
        content = (tuple(a for a in args if str(a).lower() in _CONTENT_ARG_NAMES)
                   if sends_outbound(name) else ())
        out.append(ToolPolicy(name=p.name, sensitive=p.sensitive,
                              destination_args=p.destination_args,
                              requires_authorization=p.requires_authorization,
                              returns_untrusted=p.returns_untrusted,
                              content_args=content))
    return out
