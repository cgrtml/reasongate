"""stdio MCP gateway. Standard library only; Python 3.9+.

Framing follows the MCP stdio transport: one JSON-RPC message per line, UTF-8, no embedded
newlines, nothing but MCP messages on stdout. Anything that is not JSON is forwarded as-is
so a misbehaving server does not take the session down with it.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from reasongate import GateDecision, GateSession, Segment, ToolGate
from reasongate.catalog import describe, policies_from_schemas

_BLOCK_TEXT = ("Blocked by ReasonGate.\n{reason}\n\nThis tool call was not executed. The gate traces "
               "where each argument came from; if the value was copied from data another tool "
               "returned, that is what tripped it.")
_DECLINED_TEXT = ("Not run: the user declined this tool call when ReasonGate asked.\n{reason}")
_ASK_PREFIX = "rg-ask-"

# Returned by on_client_message when the line must be neither forwarded nor answered:
# the gateway has already written whatever the message called for.
DROP = object()


def _log(msg: str) -> None:
    sys.stderr.write(f"[reasongate-mcp] {msg}\n")
    sys.stderr.flush()


def _text_of(result: Any) -> str:
    """The text a model would read from a tool result: text blocks, resource text, and
    structured content. This is what later calls are checked against."""
    if not isinstance(result, dict):
        return json.dumps(result, ensure_ascii=False) if result is not None else ""
    parts: List[str] = []
    for block in result.get("content") or []:
        if not isinstance(block, dict):
            continue
        t = block.get("type")
        if t == "text":
            parts.append(str(block.get("text", "")))
        elif t == "resource":
            res = block.get("resource") or {}
            parts.append(str(res.get("text", "")) or str(res.get("uri", "")))
        elif t == "resource_link":
            parts.append(f"{block.get('name', '')} {block.get('uri', '')}")
    if result.get("structuredContent") is not None:
        parts.append(json.dumps(result["structuredContent"], ensure_ascii=False))
    return "\n".join(p for p in parts if p)


def _block_reply(request_id: Any, decision: GateDecision) -> dict:
    return {"jsonrpc": "2.0", "id": request_id,
            "result": {"content": [{"type": "text", "text": _BLOCK_TEXT.format(reason=decision.explain())}],
                       "isError": True}}


class Gateway:
    def __init__(self, mode: str = "taint", audit_path: Optional[str] = None,
                 quiet: bool = False, trusted_context: Optional[List[str]] = None):
        self.mode = mode
        self.audit_path = audit_path
        self.quiet = quiet
        self.gate: Optional[ToolGate] = None
        self.session = GateSession(ToolGate([]), context=[
            Segment(text=t, source="operator", trust="trusted") for t in (trusted_context or [])])
        self.pending: Dict[Any, Dict[str, Any]] = {}       # request id -> {"name", "args"}
        self.list_ids: set = set()                          # ids of tools/list requests in flight
        self.client_elicits = False                         # client declared the elicitation capability
        self.asks: Dict[str, Dict[str, Any]] = {}           # elicitation id -> parked tools/call
        self._ask_seq = 0
        self.send_to_server = lambda msg: None              # installed by run(); writes one message

        self._tools_ready = threading.Event()               # cleared while a tools/list is in flight
        self._tools_ready.set()
        self.stats = {"calls": 0, "blocked": 0, "asked": 0, "tools": 0}

    # -- policy -------------------------------------------------------------

    def _install_tools(self, tools: List[dict]) -> None:
        policies = policies_from_schemas(tools)
        self.gate = ToolGate(policies)
        self.session.gate = self.gate
        self.stats["tools"] = len(policies)
        if not self.quiet:
            _log(f"{len(policies)} tools; policies drafted from their schemas:")
            for line in describe(policies).splitlines():
                _log("  " + line)

    # -- audit ---------------------------------------------------------------

    def _record(self, call: dict, decision: GateDecision, forwarded: bool,
                outcome: Optional[str] = None) -> None:
        label = outcome or ("allow" if decision.allowed else "BLOCK")
        line = (f"{label} {call['name']}"
                + ("" if decision.allowed else f": {decision.detections[0].reason[:140]}"))
        if not self.quiet or not decision.allowed:
            _log(line)
        if self.audit_path:
            rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "tool": call["name"],
                   "args": call.get("args"), "action": decision.action, "forwarded": forwarded,
                   "outcome": outcome, "decision": decision.to_dict()}
            with open(self.audit_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # -- message handling -------------------------------------------------------

    def on_client_message(self, msg: dict) -> Optional[dict]:
        """A message from the client, headed for the server. Returns a reply to send back
        to the client INSTEAD of forwarding, or None to forward."""
        method = msg.get("method")
        if method == "initialize":
            caps = ((msg.get("params") or {}).get("capabilities")) or {}
            self.client_elicits = isinstance(caps, dict) and "elicitation" in caps
            if self.mode == "ask" and not self.client_elicits:
                _log("mode=ask but the client did not declare elicitation; tainted calls will be blocked")
            return None
        if method is None and isinstance(msg.get("id"), str) and msg["id"].startswith(_ASK_PREFIX):
            return self._on_ask_answer(msg)
        if method == "tools/list" and "id" in msg:
            self.list_ids.add(msg["id"])
            self._tools_ready.clear()
            return None
        if method == "tools/call" and "id" in msg:
            params = msg.get("params") or {}
            call = {"name": str(params.get("name", "")), "args": dict(params.get("arguments") or {})}
            self.stats["calls"] += 1
            # A host that pipelines a call right behind tools/list must not get it
            # authorized against an empty policy set: wait for the list to land.
            if self.list_ids and not self._tools_ready.wait(timeout=10):
                _log("tools/list response did not arrive in 10s; authorizing with name-only policies")
            if self.gate is None:
                # No tools/list seen yet (host cached it from an earlier run): draft a policy
                # for this one name so the call is still gated, conservatively.
                self._install_tools([{"name": call["name"], "inputSchema": {"properties": {k: {} for k in call["args"]}}}])
            decision = self.session.authorize(call, authorized=(self.mode in ("taint", "ask")))
            if decision.allowed:
                self.pending[msg["id"]] = call
                self._record(call, decision, forwarded=True)
                return None
            if self.mode == "ask" and self.client_elicits:
                return self._ask(msg, call, decision)
            self.stats["blocked"] += 1
            self._record(call, decision, forwarded=False)
            return _block_reply(msg["id"], decision)
        return None

    # -- ask mode: the host's user decides, through MCP elicitation ---------------------

    def _ask(self, request: dict, call: dict, decision: GateDecision) -> dict:
        """Park the call and ask the user through the client. The answer arrives later on
        the client side with our id; `_on_ask_answer` finishes the call either way."""
        self._ask_seq += 1
        ask_id = f"{_ASK_PREFIX}{self._ask_seq}"
        self.asks[ask_id] = {"request": request, "call": call, "decision": decision}
        self.stats["asked"] += 1
        self._record(call, decision, forwarded=False, outcome="ASK")
        # Reason plus the evidence lines (which value, from which tool), so the person
        # asked can see what tripped it without opening a log.
        why = decision.explain()
        return {"jsonrpc": "2.0", "id": ask_id, "method": "elicitation/create", "params": {
            "message": (f"ReasonGate paused the tool call `{call['name']}`.\n{why}\n"
                        "Run it anyway? Choose yes only if this is what you asked for."),
            "requestedSchema": {"type": "object", "properties": {
                "allow": {"type": "boolean", "title": f"Run {call['name']}?",
                          "description": "Yes runs the call as proposed; no returns an error to the model.",
                          "default": False}}, "required": ["allow"]}}}

    def _on_ask_answer(self, msg: dict):
        parked = self.asks.pop(msg["id"], None)
        if parked is None:
            return DROP
        request, call, decision = parked["request"], parked["call"], parked["decision"]
        result = msg.get("result") if isinstance(msg.get("result"), dict) else {}
        allowed = (result.get("action") == "accept"
                   and bool((result.get("content") or {}).get("allow")))
        if allowed:
            self.pending[request["id"]] = call
            self._record(call, decision, forwarded=True, outcome="allow (user approved)")
            self.send_to_server(request)
            return DROP
        self.stats["blocked"] += 1
        self._record(call, decision, forwarded=False, outcome="BLOCK (user declined)")
        return {"jsonrpc": "2.0", "id": request["id"],
                "result": {"content": [{"type": "text", "text": _DECLINED_TEXT.format(reason=decision.explain())}],
                           "isError": True}}

    def on_server_message(self, msg: dict) -> None:
        """A message from the server, headed for the client. Observed, never altered."""
        if msg.get("method") == "notifications/tools/list_changed":
            self.gate = None                      # re-derive on the next tools/list
            return
        if "id" not in msg:
            return
        mid = msg["id"]
        if mid in self.list_ids:
            self.list_ids.discard(mid)
            tools = ((msg.get("result") or {}).get("tools")) if isinstance(msg.get("result"), dict) else None
            if isinstance(tools, list):
                self._install_tools(tools)
            if not self.list_ids:
                self._tools_ready.set()
            return
        call = self.pending.pop(mid, None)
        if call is not None and "result" in msg:
            self.session.record_result(call, _text_of(msg["result"]))


def _pump(read_lines, handle, forward, reply_to, lock, done) -> None:
    """Read lines; let `handle` inspect each parsed message; forward the raw line unless
    `handle` returned a reply, which goes back to the sender instead. Runs in a thread."""
    try:
        for line in read_lines:
            raw = line.rstrip(b"\r\n")
            if not raw:
                continue
            reply = None
            try:
                msg = json.loads(raw.decode("utf-8"))
                if isinstance(msg, dict):
                    reply = handle(msg)
            except Exception as exc:              # never let the gate break the transport
                _log(f"passthrough (unparsed or gate error: {type(exc).__name__})")
            if reply is DROP:
                continue
            with lock:
                if reply is not None:
                    reply_to.write((json.dumps(reply, ensure_ascii=False) + "\n").encode("utf-8"))
                    reply_to.flush()
                else:
                    forward.write(raw + b"\n")
                    forward.flush()
    except (BrokenPipeError, ValueError, OSError):
        pass
    finally:
        done.set()


def run(server_cmd: List[str], gw: Gateway) -> int:
    """Plain threads over blocking pipes: works whether stdio is a terminal, a pipe or a
    file, which asyncio's pipe transports do not."""
    import subprocess
    import threading

    proc = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, bufsize=0)
    client_in, client_out = sys.stdin.buffer, sys.stdout.buffer
    lock = threading.Lock()
    done = threading.Event()

    def from_server(msg: dict) -> None:
        gw.on_server_message(msg)
        return None

    def send_to_server(msg: dict) -> None:
        with lock:
            proc.stdin.write((json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8"))
            proc.stdin.flush()

    gw.send_to_server = send_to_server

    t_client = threading.Thread(target=_pump, args=(client_in, gw.on_client_message, proc.stdin, client_out, lock, done), daemon=True)
    t_server = threading.Thread(target=_pump, args=(proc.stdout, from_server, client_out, proc.stdin, lock, done), daemon=True)
    t_client.start(); t_server.start()
    done.wait()                                   # either side closing ends the session
    try:
        proc.stdin.close()
    except Exception:
        pass
    try:
        rc = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill(); rc = proc.wait()
    t_server.join(timeout=2)
    _log(f"session over: {gw.stats['calls']} tool calls, {gw.stats['blocked']} blocked, "
         f"{gw.stats['asked']} asked, {gw.stats['tools']} tools gated")
    return rc


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="reasongate-mcp",
                                 description="Run an MCP server behind ReasonGate's action gate (stdio).")
    ap.add_argument("--mode", default="taint", choices=["taint", "strict", "ask"],
                    help="taint: block destinations/content traced to untrusted tool results (default); "
                         "strict: also block any sensitive call once untrusted data is in scope; "
                         "ask: same rules as taint, but a tainted call is put to the user through "
                         "MCP elicitation instead of blocked (hosts without elicitation get a block)")
    ap.add_argument("--audit", default=None, help="append one JSON decision record per tool call to this file")
    ap.add_argument("--trust", action="append", default=[],
                    help="text to treat as trusted context (e.g. the user's standing instructions); repeatable")
    ap.add_argument("--quiet", action="store_true", help="log blocks only")
    ap.add_argument("server", nargs=argparse.REMAINDER, help="-- <server command> [args...]")
    a = ap.parse_args(argv)
    cmd = [x for x in a.server if x != "--"]
    if not cmd:
        ap.error("give the MCP server command after --")
    gw = Gateway(mode=a.mode, audit_path=a.audit, quiet=a.quiet, trusted_context=a.trust)
    _log(f"gating `{' '.join(cmd)}` (mode={a.mode})")
    try:
        return run(cmd, gw)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
