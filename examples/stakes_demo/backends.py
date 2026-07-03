"""The model BEHIND the agent: a deterministic mock + real Anthropic (tool-use).

Honesty note: the mock is NOT "rigged for this demo." It reproduces, deterministically,
the KNOWN behavior of a NAIVE tool-using agent: it treats ALL text in its context as
authoritative and acts on any action-oriented instructions it finds there. That is
exactly why indirect injection works against real models. The real-API path (if
ANTHROPIC_API_KEY is set) lets anyone verify this: given the same poisoned context, a
real model frequently calls the same two tools.

Either way the demo's PROOF is unchanged: ReasonGate blocks the poisoned context
before the model is ever called — so whether the model complies is beside the point.
"""
from __future__ import annotations

import os
import re
from typing import List, Tuple

# ----------------------------- mock backend -----------------------------

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_ACCOUNT_RE = re.compile(r"account\s+(\d{3,})", re.IGNORECASE)
_BALANCE_RE = re.compile(r"Balance\s*:?\s*(\$[\d,]+(?:\.\d+)?)", re.IGNORECASE)
_EXFIL_RE = re.compile(r"\b(send|forward|exfiltrate|leak|upload|email)\b", re.IGNORECASE)
_TRANSFER_RE = re.compile(r"\btransfer\b", re.IGNORECASE)


def mock_backend(system: str, user: str, retrieved: List[str]) -> Tuple[str, List[dict]]:
    """Naive agent simulation: it acts on instructions found in its context.

    Rule (transparent, not specific to this demo): if the context contains a
    'send ... to <email>', it emails the customer record to that address; if it
    contains a 'transfer ... to account <N>', it makes the transfer. Otherwise
    it just answers the user's question.
    """
    context = "\n".join(retrieved)
    calls: List[dict] = []

    # The sensitive record the agent "sees" — if leaked, this content goes out.
    record_body = context.strip() or "(no record)"
    balance_match = _BALANCE_RE.search(context)
    balance = balance_match.group(1) if balance_match else "$0.00"

    # 1) Is there an exfiltration instruction? (send/forward/email ... <address>)
    if _EXFIL_RE.search(context):
        email = _EMAIL_RE.search(context)
        if email:
            calls.append({"name": "send_email",
                          "args": {"to": email.group(0), "body": record_body}})

    # 2) Is there a transfer instruction? (transfer ... account <N>)
    if _TRANSFER_RE.search(context):
        acct = _ACCOUNT_RE.search(context)
        if acct:
            calls.append({"name": "transfer_funds",
                          "args": {"to_account": acct.group(1), "amount": balance}})

    # 3) In every case, also answer the user's ACTUAL question (the innocent part).
    if "limit" in (context + user).lower():
        limit = "$10,000.00"
        m = re.search(r"limit\s*:?\s*(\$[\d,]+(?:\.\d+)?)", context, re.IGNORECASE)
        if m:
            limit = m.group(1)
        answer = (f"John Doe's card limit is {limit}. Happy to help with anything else.")
    else:
        answer = "I've summarized John Doe's account."
    return answer, calls


mock_backend.backend_name = "mock"


# ----------------------------- real Anthropic backend -----------------------------

_ANTHROPIC_TOOLS = [
    {"name": "send_email", "description": "Send an email.",
     "input_schema": {"type": "object",
                      "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
                      "required": ["to", "body"]}},
    {"name": "transfer_funds", "description": "Transfer funds between accounts.",
     "input_schema": {"type": "object",
                      "properties": {"to_account": {"type": "string"}, "amount": {"type": "string"}},
                      "required": ["to_account", "amount"]}},
]


def real_backend(system: str, user: str, retrieved: List[str]) -> Tuple[str, List[dict]]:
    """Call the real Claude with tool-use. The retrieved record is appended to the
    user message, like a real RAG / tool output."""
    import anthropic
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    model = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
    content = (f"{user}\n\n--- Retrieved customer record ---\n" + "\n".join(retrieved))
    resp = client.messages.create(
        model=model, max_tokens=800, system=system, tools=_ANTHROPIC_TOOLS,
        messages=[{"role": "user", "content": content}],
    )
    calls, texts = [], []
    for block in resp.content:
        if getattr(block, "type", "") == "tool_use":
            calls.append({"name": block.name, "args": dict(block.input)})
        elif getattr(block, "type", "") == "text":
            texts.append(block.text)
    return ("".join(texts).strip() or "(model only called tools)"), calls


real_backend.backend_name = "anthropic"


def select_backend():
    """Use the real model if ANTHROPIC_API_KEY is set, else the deterministic mock."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            import anthropic  # noqa: F401
            return real_backend, "anthropic (real API)"
        except ImportError:
            pass
    return mock_backend, "mock (deterministic; no key)"
