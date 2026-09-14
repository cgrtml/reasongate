"""A starting catalog of tool policies, inferred from tool names.

The gate's honest weakness is that it only knows what the integrator declares. An
application with forty tools has to classify forty tools before the gate does
anything, and the usual outcome of that is an empty policy list and a gate that
silently allows everything.

This closes the gap between "installed" and "configured" — not the gap between
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

from reasongate.agent_gate import ToolPolicy

# Verbs and nouns that mark an irreversible or outward-facing capability: money,
# messages that leave the system, destruction, code execution, publication.
_SENSITIVE = (
    r"send|email|mail|sms|text|message|notify|post|publish|tweet|share|forward|reply|"
    r"transfer|pay|payment|purchase|buy|charge|refund|invoice|wire|withdraw|"
    r"delete|remove|destroy|drop|truncate|purge|revoke|disable|"
    r"exec|execute|run|shell|bash|command|eval|script|deploy|release|merge|push|"
    r"write|create|update|upsert|insert|modify|rename|move|copy|upload|"
    r"grant|invite|add user|add member|add participant|approve|sign|order|book|"
    r"reserve|reservation|schedule|reschedule|cancel|append|call"
)

# Tools that bring outside data in. Their results are untrusted for every later call
# in a GateSession — this is what makes taint survive more than one hop.
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
)

_SENSITIVE_RE = re.compile(rf"(?:^|[^a-z])(?:{_SENSITIVE})(?:[^a-z]|$)", re.I)
_INGEST_RE = re.compile(rf"(?:^|[^a-z])(?:{_INGEST})(?:[^a-z]|$)", re.I)


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
    sensitive = bool(_SENSITIVE_RE.search(words))
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
        dests = [a for a in known_args if a.lower() in _DESTINATION_ARGS]
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
    """A reviewable table of what was inferred — print this, then correct it."""
    rows = ["tool                           sensitive  returns-untrusted  destination args",
            "-" * 82]
    for p in policies:
        dests = ", ".join(p.destination_args) or "(all)" if p.sensitive else ""
        rows.append(f"{p.name:30} {'yes' if p.sensitive else 'no':9}  "
                    f"{'yes' if p.returns_untrusted else 'no':17}  {dests}")
    rows.append("")
    rows.append("Inferred from names. A tool whose name does not say what it does is "
                "invisible here — declare those by hand.")
    return "\n".join(rows)
