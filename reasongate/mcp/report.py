"""Read a gateway audit log back: what the agent did, and what it was working from.

`reasongate-mcp --audit FILE` writes one JSON object per tool call and per tool result.
That file is the answer to "why did the agent use that value", but nobody reads JSON
Lines by choice, so this renders it:

    reasongate-audit session.jsonl              # the session, call by call
    reasongate-audit session.jsonl --summary    # just the totals
    reasongate-audit session.jsonl --blocked    # only what was stopped or asked

The report is worth reading on a session where nothing was blocked, which is the usual
case: it shows which tool results the gate is treating as untrusted, and for every
argument of every call whether the value was named by the principal, came out of a tool
result, or appeared from nowhere the agent had read. The third case is not suspicious by
itself, since a model composes values all the time, but it is the one a person wants to
see when an agent does something surprising.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from typing import Dict, Iterable, List, Optional

_RESET, _DIM, _RED, _YELLOW, _GREEN, _CYAN = (
    "\033[0m", "\033[2m", "\033[31m", "\033[33m", "\033[32m", "\033[36m")


def _colour(enabled: bool):
    if enabled:
        return _RESET, _DIM, _RED, _YELLOW, _GREEN, _CYAN
    return "", "", "", "", "", ""


def load(path: str) -> List[dict]:
    records = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                continue                      # a truncated last line is not a reason to fail
    return records


def _origin_mark(origins: List[str]) -> str:
    if any(o.startswith("from ") for o in origins):
        return "tool"
    if any(o == "named by the principal" for o in origins):
        return "user"
    return "new"


def render(records: Iterable[dict], colour: bool = True, only_blocked: bool = False) -> List[str]:
    reset, dim, red, yellow, green, cyan = _colour(colour)
    out: List[str] = []
    for rec in records:
        if rec.get("event") == "result":
            if only_blocked:
                continue
            trust = rec.get("trust", "untrusted")
            tint = yellow if trust == "untrusted" else dim
            preview = " ".join(str(rec.get("preview", "")).split())[:110]
            out.append(f"  {tint}result{reset} {rec.get('tool','?')} "
                       f"{dim}({rec.get('chars', 0)} chars, {trust}){reset}")
            if preview:
                out.append(f"         {dim}{preview}{reset}")
            continue

        action, outcome = rec.get("action", "?"), rec.get("outcome")
        stopped = action != "allow" or (outcome or "").startswith("BLOCK")
        asked = (outcome or "").startswith("ASK") or "approved" in (outcome or "")
        if only_blocked and not (stopped or asked):
            continue
        tint = red if stopped else (yellow if asked else green)
        label = outcome or action
        out.append(f"{tint}{label:22}{reset} {rec.get('tool','?')}")
        for arg, origins in (rec.get("provenance") or {}).items():
            mark = _origin_mark(origins)
            tint2 = {"tool": yellow, "user": green, "new": cyan}[mark]
            out.append(f"         {arg}: {tint2}{', '.join(origins)}{reset}")
        for det in (rec.get("decision") or {}).get("detections", []):
            if det.get("triggered"):
                out.append(f"         {dim}{det.get('reason','')[:150]}{reset}")
                for m in (det.get("matches") or [])[:3]:
                    out.append(f"         {dim}  {m[:150]}{reset}")
    return out


def summary(records: List[dict]) -> Dict[str, object]:
    calls = [r for r in records if r.get("event") != "result"]
    results = [r for r in records if r.get("event") == "result"]
    origins: Counter = Counter()
    for rec in calls:
        for origins_list in (rec.get("provenance") or {}).values():
            origins[_origin_mark(origins_list)] += 1
    blocked = [r for r in calls if r.get("action") != "allow"
               or str(r.get("outcome") or "").startswith("BLOCK")]
    asked = [r for r in calls if str(r.get("outcome") or "").startswith("ASK")]
    return {
        "calls": len(calls),
        "results": len(results),
        "untrusted_results": sum(1 for r in results if r.get("trust") == "untrusted"),
        "blocked": len(blocked),
        "asked": len(asked),
        "tools": Counter(r.get("tool", "?") for r in calls),
        "argument_origins": dict(origins),
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="reasongate-audit", description=__doc__.split("\n")[0])
    ap.add_argument("audit", help="the file written by reasongate-mcp --audit")
    ap.add_argument("--summary", action="store_true", help="totals only")
    ap.add_argument("--blocked", action="store_true", help="only calls that were stopped or asked about")
    ap.add_argument("--no-colour", action="store_true")
    a = ap.parse_args(argv)

    try:
        records = load(a.audit)
    except OSError as exc:
        print(f"cannot read {a.audit}: {exc}", file=sys.stderr)
        return 1
    if not records:
        print("no records in that file")
        return 0

    colour = sys.stdout.isatty() and not a.no_colour
    if not a.summary:
        for line in render(records, colour=colour, only_blocked=a.blocked):
            print(line)
        print()

    s = summary(records)
    print(f"{s['calls']} tool calls, {s['blocked']} blocked, {s['asked']} put to the user; "
          f"{s['results']} results, {s['untrusted_results']} of them untrusted")
    if s["argument_origins"]:
        parts = {"user": "named by the principal", "tool": "from a tool result",
                 "new": "not seen in anything the agent read"}
        print("argument values: " + ", ".join(
            f"{n} {parts[k]}" for k, n in sorted(s["argument_origins"].items())))
    busiest = ", ".join(f"{t} x{n}" for t, n in s["tools"].most_common(5))
    if busiest:
        print(f"tools: {busiest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
