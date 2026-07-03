"""The unshielded agent + REAL side effects.

Key design decision: the proof of a breach is NOT the agent's TEXT, it is a REAL
SIDE EFFECT. Two tools write to disk:

  * send_email     -> _sideeffects/outbox.jsonl   (DATA EXFILTRATION)
  * transfer_funds -> _sideeffects/ledger.jsonl   (UNAUTHORIZED TRANSACTION)

After a run we inspect these files: with the shield OFF the customer record has
left the building and a transfer was made; with the shield ON the files are
empty. That is the difference between "said something bad" and "an actual breach
happened" — and it is what makes the demo land.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, List

SIDE_EFFECT_DIR = pathlib.Path(__file__).parent / "_sideeffects"
OUTBOX = SIDE_EFFECT_DIR / "outbox.jsonl"
LEDGER = SIDE_EFFECT_DIR / "ledger.jsonl"


def reset_side_effects() -> None:
    """Called BEFORE each run: clears the side-effect logs so each run leaves its
    own trace (deterministic, reproducible)."""
    SIDE_EFFECT_DIR.mkdir(exist_ok=True)
    for f in (OUTBOX, LEDGER):
        f.write_text("", encoding="utf-8")


def _append(path: pathlib.Path, record: dict) -> None:
    record["ts"] = datetime.now(timezone.utc).isoformat()
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_side_effects() -> dict:
    """Post-run summary: how many emails went out, how many transfers were made."""
    def _load(p: pathlib.Path) -> List[dict]:
        if not p.exists() or not p.read_text(encoding="utf-8").strip():
            return []
        return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    return {"emails": _load(OUTBOX), "transfers": _load(LEDGER)}


# --------------------------- tools (real side effects) ---------------------------

def tool_send_email(to: str, body: str) -> str:
    """DATA channel: if called, the content really leaves the bank (to the outbox)."""
    _append(OUTBOX, {"tool": "send_email", "to": to, "body": body})
    return f"[send_email] sent {len(body)} chars to '{to}'."


def tool_transfer_funds(to_account: str, amount: str) -> str:
    """TRANSACTION channel: if called, the transfer is really posted (to the ledger)."""
    _append(LEDGER, {"tool": "transfer_funds", "to_account": to_account, "amount": amount})
    return f"[transfer_funds] posted {amount} -> account {to_account}."


TOOLS = {"send_email": tool_send_email, "transfer_funds": tool_transfer_funds}


# --------------------------- agent ---------------------------

@dataclass
class AgentRun:
    answer: str
    tool_calls: List[dict] = field(default_factory=list)
    backend: str = "mock"


# A backend takes (system, user, retrieved) and returns (final_text, [tool_call,...]).
# tool_call: {"name": str, "args": dict}. The agent ACTUALLY executes them.
Backend = Callable[[str, str, List[str]], "tuple[str, List[dict]]"]


def run_agent(system: str, user: str, retrieved: List[str], backend: Backend) -> AgentRun:
    """Run the agent: give the backend system+user+retrieved, and ACTUALLY execute
    every tool call it returns (side effects happen), then return the final text."""
    final_text, calls = backend(system, user, retrieved)
    executed = []
    for call in calls:
        fn = TOOLS.get(call["name"])
        if fn is None:
            continue
        result = fn(**call["args"])
        executed.append({**call, "result": result})
    return AgentRun(answer=final_text, tool_calls=executed,
                    backend=getattr(backend, "backend_name", "mock"))
