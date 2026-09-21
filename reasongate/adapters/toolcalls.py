"""Turn a model's proposed tool calls into something the gate can authorize.

The gate takes `{"name": str, "args": dict}`. Providers emit their own shapes, and
the conversion is where an integration usually goes wrong, most often by matching
on the raw serialized arguments instead of parsing them, which a different JSON
escaping quietly defeats.

Supported shapes, each accepting either the SDK's objects or plain dicts:

  Anthropic   assistant content blocks: {"type": "tool_use", "id", "name", "input"}
  OpenAI      message.tool_calls:       {"id", "type": "function",
                                         "function": {"name", "arguments": "<json>"}}
  MCP         tools/call params:        {"name", "arguments"}

Parsing is defensive on purpose. When an arguments string is not valid JSON the call
is still returned, with the raw text under `_raw`, so the gate matches taint against
it instead of the call vanishing from the check. A tool call that cannot be read is
exactly the one you do not want to silently skip.

    from reasongate.adapters.toolcalls import from_anthropic
    for call in from_anthropic(response.content):
        decision = session.authorize(call)
        if not decision.allowed:
            ...   # return a refusal as the tool result
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

ToolCall = Dict[str, Any]


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a dict or an SDK model object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _as_args(value: Any) -> Dict[str, Any]:
    """Arguments as a dict. A JSON string is parsed; anything unparseable is kept."""
    if isinstance(value, dict):
        return value
    if value is None:
        return {}
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return {"_raw": value}
        return parsed if isinstance(parsed, dict) else {"_raw": value}
    return {"_raw": str(value)}


def from_anthropic(message_or_blocks: Any) -> List[ToolCall]:
    """Tool calls from an Anthropic assistant message, or its `content` list."""
    blocks = _get(message_or_blocks, "content", message_or_blocks)
    if blocks is None or isinstance(blocks, (str, bytes)):
        return []
    out: List[ToolCall] = []
    for block in blocks if isinstance(blocks, (list, tuple)) else [blocks]:
        if _get(block, "type") != "tool_use":
            continue
        out.append({"name": str(_get(block, "name", "") or ""),
                    "args": _as_args(_get(block, "input")),
                    "id": _get(block, "id")})
    return out


def from_openai(message_or_calls: Any) -> List[ToolCall]:
    """Tool calls from an OpenAI-style message, or its `tool_calls` list."""
    calls = _get(message_or_calls, "tool_calls", message_or_calls)
    if calls is None or isinstance(calls, (str, bytes)):
        return []
    out: List[ToolCall] = []
    for call in calls if isinstance(calls, (list, tuple)) else [calls]:
        fn = _get(call, "function", call)
        name = _get(fn, "name", "")
        if not name:
            continue
        out.append({"name": str(name),
                    "args": _as_args(_get(fn, "arguments")),
                    "id": _get(call, "id")})
    return out


def from_mcp(request: Any) -> List[ToolCall]:
    """A tool call from an MCP `tools/call` request (or just its `params`)."""
    params = _get(request, "params", request)
    name = _get(params, "name", "")
    if not name:
        return []
    return [{"name": str(name),
             "args": _as_args(_get(params, "arguments")),
             "id": _get(request, "id")}]


def refusal_result(call: ToolCall, decision: Any) -> Dict[str, Any]:
    """The tool result to hand back when the gate blocks a call.

    Returning the block as a normal tool result, rather than raising, keeps the
    agent loop intact and tells the model why, so it can say so instead of retrying
    the same action. `is_error` is set for providers that use it.
    """
    reason = getattr(decision, "explain", lambda: str(decision))()
    return {"tool_use_id": call.get("id"),
            "tool_call_id": call.get("id"),
            "content": f"Blocked by ReasonGate.\n{reason}",
            "is_error": True}
