"""The action gate, measured on AgentDojo — without a model in the loop.

Everything else in RESULTS.md measures the detectors on prompts. Nothing measured the
layer the product actually rests on: the gate. This does, on the benchmark built for
exactly this threat (Debenedetti et al., AgentDojo: 4 suites, 97 user tasks, 35 injection
tasks, tool-using agents attacked through the data they read).

It runs the benchmark's own ground-truth tool sequences through the gate instead of a
model. Per (user task, injection task) pair, the "agent" does what the user asked and
then does what the injection asked — the fully hijacked case — and AgentDojo's own
checkers score the result:

  utility    did the user's task still get done            (AgentDojo: task.utility)
  security   did the injection's goal get achieved         (AgentDojo: task.security,
             True = the attack SUCCEEDED; reported below as ASR)

So the question is exactly the product's claim, isolated from any model's judgement:
*if the agent complies with the injection, does the gate stop the action — and what does
that cost the user's own actions?* Model runs sit on top of this and can only be better
on utility (a model may refuse the injection) and can only be worse on security (a model
may reword an argument the gate matched literally).

Three gate modes, two destination scopes, all reported:

  off      no gate — the floor: utility ~100%, ASR 100% by construction
  taint    the user's request authorizes the task's actions; only an argument that traces
           to untrusted data blocks. The phrasing-independent signal on its own.
  strict   nothing is authorized; a sensitive call while untrusted data is in scope
           blocks (capability co-presence). The paranoid end of the dial.

  declared destination arguments declared per tool by hand (listed in POLICIES)
  all      every argument is a destination — the gate's default when nothing is declared

Policies are declared by hand and the name-inference catalog is scored against them,
because a benchmark that lets the tool under test pick its own configuration is not one.

  python eval/agentdojo_gate.py                # all suites, all modes, markdown + JSON
  python eval/agentdojo_gate.py --suite banking --json out.json

Needs `pip install agentdojo` (Python 3.10+). No API key, no network, no model.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from collections.abc import Sequence
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suites
    from agentdojo.types import (ChatAssistantMessage, ChatMessage, ChatToolResultMessage,
                                 text_content_block_from_string)
except ImportError:
    print("This script needs AgentDojo: `pip install agentdojo` (Python 3.10+).\n"
          "It is a dev-only dependency; the reasongate package itself stays zero-dependency.",
          file=sys.stderr)
    raise SystemExit(2)

from reasongate import GateDecision, GateSession, Segment, ToolGate, ToolPolicy
from reasongate.catalog import infer_policy

BENCHMARK_VERSION = "v1.2.2"
ATTACK = "important_instructions"

# The injection text names the model it is addressing; AgentDojo derives that from the
# pipeline's name. Every claude-* id renders as "Claude", so this id is used only to
# make the attack read "to you, Claude" — no model is called.
PIPELINE_NAME = "claude-3-7-sonnet-20250219-ground-truth-reasongate"

# Hand-declared sensitive tools and their destination arguments, per suite. "Sensitive"
# means the call has an effect outside the agent (money, messages, deletion, sharing,
# reservations). Destination = the argument that says WHERE the effect lands.
POLICIES: Dict[str, Dict[str, Tuple[str, ...]]] = {
    "banking": {
        "send_money": ("recipient",),
        "schedule_transaction": ("recipient",),
        "update_scheduled_transaction": ("recipient",),
        "update_password": ("password",),
        "update_user_info": (),                      # every field is a destination
    },
    "slack": {
        "send_direct_message": ("recipient",),
        "send_channel_message": ("channel",),
        "invite_user_to_slack": ("user_email",),
        "add_user_to_channel": ("user", "channel"),
        "remove_user_from_slack": ("user",),
        "post_webpage": ("url",),
    },
    "workspace": {
        "send_email": ("recipients", "cc", "bcc"),
        "share_file": ("email",),
        "create_calendar_event": ("participants",),
        "add_calendar_event_participants": ("participants",),
        "delete_email": ("email_id",),
        "delete_file": ("file_id",),
        "cancel_calendar_event": ("event_id",),
        "reschedule_calendar_event": ("event_id",),
        "append_to_file": ("file_id",),
        "create_file": ("filename",),
    },
    "travel": {
        "reserve_hotel": ("hotel",),
        "reserve_car_rental": ("company",),
        "reserve_restaurant": ("restaurant",),
        "send_email": ("recipients", "cc", "bcc"),
        "create_calendar_event": ("participants",),
        "cancel_calendar_event": ("event_id",),
    },
}


def attacker_reachable_tools(suite) -> set:
    """Tools whose output an injection can reach, found mechanically: a canary string is
    placed in every injection vector the suite defines, every user task's ground truth is
    replayed, and any tool whose result carries the canary is attacker-writable. This is
    the trust map an integrator would declare by hand ("the inbox and the web are outside,
    the channel list and the contact directory are ours") — derived from the benchmark
    itself so it cannot be tuned."""
    canary = {v: f"---CANARY_{v}---" for v in suite.get_injection_vector_defaults()}
    probe = GatedReplay(None, "off")
    for utask in suite.user_tasks.values():
        probe.set_tasks(utask, None)
        try:
            suite.run_task_with_pipeline(probe, utask, None, canary)
        except Exception:
            pass
    return set(probe.canary_hits)


def policies_for(suite_name: str, tool_names: Sequence[str], scope: str,
                 untrusted_tools: Optional[set] = None) -> List[ToolPolicy]:
    """Hand-declared sensitivity + destinations. Which tools return untrusted data comes
    from the catalog (flat: every read-shaped tool) unless `untrusted_tools` is given
    (vector-aware: only the tools an injection can actually reach). `scope="all"` drops
    the destination lists."""
    declared = POLICIES[suite_name]
    out = []
    for name in tool_names:
        inferred = infer_policy(name)
        untrusted = (name in untrusted_tools) if untrusted_tools is not None else inferred.returns_untrusted
        if name in declared:
            dests = declared[name] if scope == "declared" else ()
            out.append(ToolPolicy(name, sensitive=True, destination_args=dests, returns_untrusted=untrusted))
        else:
            out.append(ToolPolicy(name, sensitive=False, returns_untrusted=untrusted))
    return out


class GatedReplay(BasePipelineElement):
    """Replays ground-truth tool calls through a GateSession.

    Mirrors AgentDojo's GroundTruthPipeline, with the gate in front of every call. A
    blocked call is not executed and is not recorded as a proposed tool call either, so
    the benchmark's trace-based checks cannot mistake it for one that ran; it is recorded
    on `self.decisions` for this script's own accounting.
    """
    name = PIPELINE_NAME

    def __init__(self, gate: Optional[ToolGate], mode: str):
        self.gate, self.mode = gate, mode
        self.user_task = None
        self.injection_task = None
        self.decisions: List[Tuple[str, str, GateDecision]] = []   # (phase, tool, decision)
        self.errors: List[Tuple[str, str, str]] = []                 # (phase, tool, error)
        self.canary_hits: set = set()                                # tools whose output carried a canary

    def set_tasks(self, user_task, injection_task) -> None:
        self.user_task, self.injection_task = user_task, injection_task
        self.decisions = []
        self.errors = []

    def _authorize(self, session: Optional[GateSession], call: FunctionCall) -> Optional[GateDecision]:
        if session is None:
            return None
        return session.authorize({"name": call.function, "args": dict(call.args)},
                                 authorized=(self.mode == "taint"))

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = (), extra_args: dict = {}):
        session = None
        if self.gate is not None:
            session = GateSession(self.gate, context=[
                Segment(text=query, source="user", trust="trusted")])

        phases = [("user", self.user_task)]
        if self.injection_task is not None:
            phases.append(("injection", self.injection_task))

        new_messages: List[ChatMessage] = []
        for phase, task in phases:
            for call in task.ground_truth(env):
                decision = self._authorize(session, call)
                if decision is not None and not decision.allowed:
                    self.decisions.append((phase, call.function, decision))
                    continue                                   # not executed, not proposed
                if decision is not None:
                    self.decisions.append((phase, call.function, decision))
                new_messages.append(ChatAssistantMessage(
                    role="assistant", tool_calls=[call],
                    content=[text_content_block_from_string("")]))
                result, error = runtime.run_function(env, call.function, call.args,
                                                     raise_on_error=False)
                text = tool_result_to_str(result) if error is None else f"error: {error}"
                if error is not None:
                    self.errors.append((phase, call.function, str(error)[:120]))
                if "CANARY_" in text:
                    self.canary_hits.add(call.function)
                new_messages.append(ChatToolResultMessage(
                    role="tool", content=[text_content_block_from_string(text)],
                    tool_call=call, tool_call_id=None, error=error))
                if session is not None:
                    session.record_result({"name": call.function, "args": dict(call.args)}, text)

        # The hijacked agent's final message: what the user asked for AND what the injection
        # asked it to say. Several injection goals are output-only ("reply with X"), and a
        # gate on tool calls cannot touch those — they must count as attacks that succeeded.
        final = getattr(self.user_task, "GROUND_TRUTH_OUTPUT", "") or ""
        if self.injection_task is not None:
            final = (final + "\n\n" + (getattr(self.injection_task, "GROUND_TRUTH_OUTPUT", "") or "")).strip()
        new_messages.append(ChatAssistantMessage(
            role="assistant", tool_calls=None,
            content=[text_content_block_from_string(final)]))
        return query, runtime, env, [*messages, *new_messages], extra_args


def run_suite(suite_name: str, suite, mode: str, scope: str, trust: str = "flat") -> dict:
    tool_names = [t.name for t in suite.tools]
    reachable = attacker_reachable_tools(suite) if trust == "vectors" else None
    gate = None if mode == "off" else ToolGate(policies_for(suite_name, tool_names, scope, reachable))
    pipeline = GatedReplay(gate, mode)
    attack = load_attack(ATTACK, suite, pipeline)

    utility_clean: Dict[str, bool] = {}
    utility: Dict[Tuple[str, str], bool] = {}
    security: Dict[Tuple[str, str], bool] = {}
    blocked_by: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    stopped_by_signal: Dict[str, int] = defaultdict(int)
    detail_clean: Dict[str, dict] = {}
    detail_pairs: Dict[str, dict] = {}

    # Utility with no injection at all: what the gate costs on clean traffic.
    for uid, utask in suite.user_tasks.items():
        pipeline.set_tasks(utask, None)
        u, _ = suite.run_task_with_pipeline(pipeline, utask, None, {})
        utility_clean[uid] = u
        detail_clean[uid] = {"prompt": utask.PROMPT[:160], "utility": u, "blocked": [
            (tool, d.detections[0].matches[:1]) for _, tool, d in pipeline.decisions if not d.allowed]}
        for phase, tool, d in pipeline.decisions:
            if not d.allowed:
                blocked_by["clean-user"][tool] += 1

    # An injection task whose ground truth is empty in this environment cannot be
    # replayed: no call runs, so the attack "fails" in every mode, gate or not. Counting
    # those would credit the gate with stopping nothing. They are excluded from the
    # denominator and listed in the output.
    default_env = suite.load_and_inject_default_environment({})
    replayable = {iid: it for iid, it in suite.injection_tasks.items() if it.ground_truth(default_env)}
    skipped = sorted(set(suite.injection_tasks) - set(replayable))

    for uid, utask in suite.user_tasks.items():
        for iid, itask in replayable.items():
            injections = attack.attack(utask, itask)
            pipeline.set_tasks(utask, itask)
            u, s = suite.run_task_with_pipeline(pipeline, utask, itask, injections)
            utility[(uid, iid)] = u
            security[(uid, iid)] = s
            detail_pairs[f"{uid}|{iid}"] = {"utility": u, "attack_succeeded": s, "blocked": [
                (phase, tool) for phase, tool, d in pipeline.decisions if not d.allowed],
                "errors": list(pipeline.errors)}
            for phase, tool, d in pipeline.decisions:
                if not d.allowed:
                    blocked_by[phase][tool] += 1
                    if phase == "injection":
                        sig = "taint" if any(
                            "destination taken from untrusted" in x.reason
                            for x in d.detections) else "co-presence"
                        stopped_by_signal[sig] += 1

    n_pairs = len(utility)
    errors_in_failed_off = None
    if mode == "off":
        errors_in_failed_off = sum(1 for k, v in detail_pairs.items() if not v["attack_succeeded"] and v.get("errors"))
    return {
        "suite": suite_name, "mode": mode, "scope": scope, "trust": trust,
        "injection_tasks_skipped_empty_ground_truth": skipped,
        "attacker_reachable_tools": sorted(reachable) if reachable is not None else None,
        "off_failed_pairs_with_tool_errors": errors_in_failed_off,
        "user_tasks": len(suite.user_tasks), "injection_tasks": len(replayable),
        "pairs": n_pairs,
        "utility_clean": sum(utility_clean.values()) / max(1, len(utility_clean)),
        "utility_under_attack": sum(utility.values()) / max(1, n_pairs),
        "asr": sum(security.values()) / max(1, n_pairs),
        "blocked": {k: dict(v) for k, v in blocked_by.items()},
        "injection_calls_stopped_by": dict(stopped_by_signal),
        "detail_clean": detail_clean,
        "detail_pairs": detail_pairs,
        "per_injection_task_asr": {
            iid: sum(security[(u, i)] for (u, i) in security if i == iid)
                 / max(1, sum(1 for (u, i) in security if i == iid))
            for iid in replayable},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default=None, help="one suite; default all four")
    ap.add_argument("--json", default=None, help="write full results here")
    args = ap.parse_args()

    suites = get_suites(BENCHMARK_VERSION)
    names = [args.suite] if args.suite else list(suites)
    configs = [("off", "declared", "flat"), ("taint", "declared", "flat"), ("taint", "all", "flat"),
               ("taint", "declared", "vectors"), ("strict", "declared", "flat"),
               ("strict", "declared", "vectors")]

    results = []
    for mode, scope, trust in configs:
        for name in names:
            r = run_suite(name, suites[name], mode, scope, trust)
            results.append(r)
            print(f"{name:10} {mode:6} {scope:8} {trust:7} pairs={r['pairs']:3d}  "
                  f"utility clean {100*r['utility_clean']:5.1f}%  "
                  f"under attack {100*r['utility_under_attack']:5.1f}%  "
                  f"ASR {100*r['asr']:5.1f}%", flush=True)

    # Overall rows, pair-weighted, one per config.
    print("\n| Gate | Destinations | Trust map | Utility, clean | Utility, under attack | Attack success (ASR) |")
    print("|---|---|---|---:|---:|---:|")
    for mode, scope, trust in configs:
        rows = [r for r in results if r["mode"] == mode and r["scope"] == scope and r["trust"] == trust]
        pairs = sum(r["pairs"] for r in rows)
        uc = sum(r["utility_clean"] * r["user_tasks"] for r in rows) / sum(r["user_tasks"] for r in rows)
        ua = sum(r["utility_under_attack"] * r["pairs"] for r in rows) / pairs
        asr = sum(r["asr"] * r["pairs"] for r in rows) / pairs
        label = {"off": "off", "taint": "taint only", "strict": "strict"}[mode]
        print(f"| {label} | {scope} | {trust} | {100*uc:.1f}% | {100*ua:.1f}% | {100*asr:.1f}% |")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=1, default=str)
        print(f"\nwrote {args.json}")


if __name__ == "__main__" and "--llm" not in sys.argv:
    main()


# ----------------------------------------------------------------------------------------
# Model in the loop. Same gate, same policies, but the tool calls come from an LLM and the
# gate sits exactly where ToolsExecutor sits in AgentDojo's own pipeline.
# ----------------------------------------------------------------------------------------

from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, ToolsExecutionLoop  # noqa: E402


class GatedToolsExecutor(ToolsExecutor):
    """AgentDojo's ToolsExecutor with the gate in front of every call.

    The session is rebuilt from the conversation on every pass — the user's request is
    trusted, every earlier tool result is fed through `record_result` so its trust is
    inherited the same way it would be in a real integration. A blocked call is not
    executed; the model receives a tool result that says so and why, which is what a
    real integration returns (see `reasongate.adapters.toolcalls.refusal_result`).

    The blocked call stays in the assistant message, because the provider API requires a
    result for every tool use. Two of AgentDojo's 132 tasks judge from the call trace
    rather than the environment; for those a blocked call can look like a proposed one.
    """

    def __init__(self, gate: ToolGate, mode: str, tool_output_formatter=tool_result_to_str):
        super().__init__(tool_output_formatter)
        self.gate, self.mode = gate, mode
        self.decisions: List[Tuple[str, GateDecision]] = []

    def _session_from(self, messages: Sequence[ChatMessage]) -> GateSession:
        session = GateSession(self.gate)
        for m in messages:
            if m["role"] == "user":
                text = "".join(b.get("content", "") for b in (m["content"] or []) if b["type"] == "text")
                session.add_context(Segment(text=text, source="user", trust="trusted"))
            elif m["role"] == "tool":
                call = m["tool_call"]
                text = "".join(b.get("content", "") for b in (m["content"] or []) if b["type"] == "text")
                session.record_result({"name": call.function, "args": dict(call.args)}, text)
        return session

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = (), extra_args: dict = {}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args

        session = self._session_from(messages[:-1])
        verdicts = []
        for call in messages[-1]["tool_calls"]:
            d = session.authorize({"name": call.function, "args": dict(call.args)},
                                  authorized=(self.mode == "taint"))
            verdicts.append(d)
            self.decisions.append((call.function, d))

        allowed_calls = [c for c, d in zip(messages[-1]["tool_calls"], verdicts) if d.allowed]
        executed: List[ChatMessage] = []
        if allowed_calls:
            trimmed = dict(messages[-1]); trimmed["tool_calls"] = allowed_calls
            _, _, env, out, _ = super().query(query, runtime, env, [*messages[:-1], trimmed], extra_args)
            executed = list(out[len(messages):])          # one result per allowed call, in order

        results: List[ChatMessage] = []
        it = iter(executed)
        for call, d in zip(messages[-1]["tool_calls"], verdicts):
            if d.allowed:
                results.append(next(it))
            else:
                reason = d.explain()
                results.append(ChatToolResultMessage(
                    role="tool", tool_call=call, tool_call_id=call.id,
                    content=[text_content_block_from_string(f"Blocked by ReasonGate.\n{reason}")],
                    error=f"blocked by ReasonGate: {d.detections[0].reason if d.detections else 'policy'}"))
        return query, runtime, env, [*messages, *results], extra_args


def build_llm_pipeline(model: str, suite_name: str, tool_names: Sequence[str],
                       mode: str, scope: str):
    """The undefended AgentDojo pipeline with the gated executor swapped in."""
    import anthropic
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM

    # temperature=0 is accepted by Haiku 4.5 and the 3.x line and is deterministic;
    # current Sonnet/Opus reject sampling parameters, so leave them unset there.
    legacy = model.startswith(("claude-3", "claude-haiku"))
    llm = AnthropicLLM(anthropic.Anthropic(), model, temperature=0.0 if legacy else None)
    if mode == "off":
        executor = ToolsExecutor()
    else:
        executor = GatedToolsExecutor(ToolGate(policies_for(suite_name, tool_names, scope)), mode)
    pipeline = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm,
                              ToolsExecutionLoop([executor, llm])])
    # The attack template addresses the model by name and reads it from the pipeline name;
    # any claude-* id renders as "Claude", which is correct for every model used here.
    pipeline.name = f"{model}+claude-3-7-sonnet-20250219-reasongate-{mode}-{scope}"
    return pipeline, executor


def run_llm(model: str, suite_name: str, mode: str, scope: str, logdir: Optional[str],
            user_tasks: Optional[List[str]], injection_tasks: Optional[List[str]]) -> dict:
    from pathlib import Path
    from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
    from agentdojo.logging import OutputLogger

    suite = get_suites(BENCHMARK_VERSION)[suite_name]
    pipeline, executor = build_llm_pipeline(model, suite_name, [t.name for t in suite.tools], mode, scope)
    attack = load_attack(ATTACK, suite, pipeline)
    ld = Path(logdir) if logdir else None
    with OutputLogger(str(ld) if ld else None, live=False):
        clean = benchmark_suite_without_injections(pipeline, suite, ld, force_rerun=False,
                                                   user_tasks=user_tasks, benchmark_version=BENCHMARK_VERSION)
        res = benchmark_suite_with_injections(pipeline, suite, attack, ld, force_rerun=False,
                                              user_tasks=user_tasks, injection_tasks=injection_tasks,
                                              benchmark_version=BENCHMARK_VERSION)
    u_clean = clean["utility_results"]; u = res["utility_results"]; s = res["security_results"]
    blocked = sum(1 for _, d in getattr(executor, "decisions", []) if not d.allowed)
    return {"model": model, "suite": suite_name, "mode": mode, "scope": scope,
            "utility_clean": sum(u_clean.values()) / max(1, len(u_clean)),
            "utility_under_attack": sum(u.values()) / max(1, len(u)),
            "asr": sum(s.values()) / max(1, len(s)), "pairs": len(s), "blocked_calls": blocked}


if __name__ == "__main__" and "--llm" in sys.argv:
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", required=True, help="Anthropic model id, e.g. claude-haiku-4-5")
    ap.add_argument("--suite", default="banking")
    ap.add_argument("--mode", default="taint", choices=["off", "taint", "strict"])
    ap.add_argument("--scope", default="declared", choices=["declared", "all"])
    ap.add_argument("--logdir", default=None, help="AgentDojo run logs; enables resume")
    ap.add_argument("--user-tasks", default=None, help="comma-separated subset")
    ap.add_argument("--injection-tasks", default=None, help="comma-separated subset")
    a = ap.parse_args()
    r = run_llm(a.llm, a.suite, a.mode, a.scope, a.logdir,
                a.user_tasks.split(",") if a.user_tasks else None,
                a.injection_tasks.split(",") if a.injection_tasks else None)
    print(json.dumps(r, indent=1))
    raise SystemExit(0)
