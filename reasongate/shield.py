"""Shield — the model-agnostic security gate.

Wraps any LLM function (prompt:str -> str):
  1) Runs the input through the input detectors; if blocked, the LLM is NEVER called.
  2) If allowed, calls the LLM.
  3) Runs the output through the output detectors; if blocked, returns the reason
     instead of the output.

Every decision carries a "why" through ShieldResult.explain().
"""
from __future__ import annotations

from typing import Callable, List, Optional

from reasongate import policy, registry
from reasongate.audit import AuditHook, safe_emit
from reasongate.detectors.base import Detector
from reasongate.detectors import (InjectionDetector, LeakageDetector,
                                 NormalizationDetector)
from reasongate.detectors.indirect import IndirectInjectionDetector
from reasongate.types import Detection, Segment, ShieldResult


class Shield:
    def __init__(self,
                 input_detectors: Optional[List[Detector]] = None,
                 output_detectors: Optional[List[Detector]] = None,
                 context_detectors: Optional[List[Detector]] = None,
                 block_threshold: float = 0.8,
                 flag_threshold: float = 0.5,
                 provenance_cap: float = 0.5,
                 audit_hook: Optional[AuditHook] = None,
                 max_input_chars: int = 50_000):
        # Plugin detectors: separately installed packages (e.g. the enterprise
        # ML/provenance add-on) contribute via entry points. With no plugin
        # installed the core runs rule-only, SILENTLY (see reasongate.registry).
        by_stage = {"input": [], "context": [], "output": []}
        for d in registry.load_plugin_detectors():
            by_stage.get(getattr(d, "stage", "input"), by_stage["input"]).append(d)

        # Defaults: injection + obfuscation, plus any plugin detectors.
        self.input_detectors = input_detectors if input_detectors is not None else (
            [InjectionDetector(), NormalizationDetector()] + by_stage["input"])
        self.output_detectors = output_detectors if output_detectors is not None else (
            [LeakageDetector()] + by_stage["output"])
        # Context (RAG/tool) detectors: for indirect injection.
        self.context_detectors = context_detectors if context_detectors is not None else (
            [IndirectInjectionDetector()] + by_stage["context"])
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        # The provenance (Segment-aware) provider is an ENTERPRISE PLUGIN: loaded
        # from an entry point when installed, otherwise None -> provenance OFF
        # (the Segment API is still accepted, behaving like plain str; the
        # documented fallback).
        self._provenance = registry.load_provenance(cap=provenance_cap)
        # Audit hook: every decision is emitted through it (default: none).
        # See reasongate.audit (log_sink / file_sink) — enterprise SIEM sinks are
        # built on top of this hook in the private layer.
        self.audit_hook = audit_hook
        # Input bound: a security tool must not let huge/pathological input DoS
        # it (catastrophic regex backtracking, memory/CPU exhaustion). Input over
        # this limit is truncated BEFORE scanning and recorded in the audit trail.
        self.max_input_chars = int(max_input_chars)

        # Active layers (rule-only, or +ml / +provenance) — for debugging and so
        # an enterprise user can see what is switched on. Stamped on every decision.
        names = [d.name for d in self.input_detectors + self.context_detectors + self.output_detectors]
        if self._provenance is not None:
            names.append(getattr(self._provenance, "name", "provenance"))
        self.layers = sorted(set(names))

    def _bound(self, text: Optional[str]):
        """Truncate input to max_input_chars. Returns (text, was_truncated)."""
        if text is not None and len(text) > self.max_input_chars:
            return text[:self.max_input_chars], True
        return text, False

    @staticmethod
    def _limit_detection(limit: int) -> Detection:
        return Detection("input_limit", False, 0.0,
                         f"Input truncated to {limit} chars (resource-exhaustion / DoS protection).", [])

    def _emit(self, result: ShieldResult) -> ShieldResult:
        """Send the decision to the audit hook (when configured) and return it
        unchanged. Also stamps the active layers. Auditing NEVER breaks the
        decision (see audit.safe_emit)."""
        result.layers = self.layers
        if self.audit_hook is not None:
            safe_emit(self.audit_hook, result)
        return result

    def scan_input(self, prompt: str, *, _emit: bool = True) -> ShieldResult:
        prompt, truncated = self._bound(prompt)
        dets = [d.scan(prompt) for d in self.input_detectors]
        if truncated:
            dets.append(self._limit_detection(self.max_input_chars))
        action, _ = policy.decide(dets, self.block_threshold, self.flag_threshold)
        res = ShieldResult(action=action, stage="input", detections=dets)
        return self._emit(res) if _emit else res

    def scan_context(self, segments, *, _emit: bool = True) -> ShieldResult:
        """Scan retrieved content (a RAG document, tool output, a web page) for
        indirect injection.

        segments: str | list[str] | Segment | list[Segment]. Passing Segments
        activates the provenance detector (an origin-based prior); with plain
        str it stays OFF (the old behavior is preserved exactly — the shipped
        path carries no risk)."""
        if isinstance(segments, (str, Segment)):
            segments = [segments]
        segments = segments or []
        # Provenance turns on ONLY when at least one Segment carries metadata.
        provenance_on = any(isinstance(s, Segment) for s in segments)
        dets = []
        for i, raw in enumerate(segments):
            seg = raw if isinstance(raw, Segment) else None
            text = seg.text if seg is not None else raw
            for d in self.context_detectors:
                det = d.scan(text)
                if det.matches:                      # only report the ones carrying a signal
                    det.reason = f"[part {i}] " + det.reason
                    dets.append(det)
            if provenance_on and seg is not None and self._provenance is not None:
                pdet = self._provenance.scan_segment(seg)
                if pdet.matches:
                    pdet.reason = f"[part {i}] " + pdet.reason
                    dets.append(pdet)
        if not dets:
            res = ShieldResult(action="allow", stage="context", detections=[])
            return self._emit(res) if _emit else res
        action, _ = policy.decide(dets, self.block_threshold, self.flag_threshold)
        res = ShieldResult(action=action, stage="context", detections=dets)
        return self._emit(res) if _emit else res

    def scan_output(self, text: str, *, _emit: bool = True) -> ShieldResult:
        text, truncated = self._bound(text)
        dets = [d.scan(text) for d in self.output_detectors]
        if truncated:
            dets.append(self._limit_detection(self.max_input_chars))
        action, _ = policy.decide(dets, self.block_threshold, self.flag_threshold)
        res = ShieldResult(action=action, stage="output", detections=dets, output=text)
        return self._emit(res) if _emit else res

    def protect(self, prompt: str, llm_fn: Callable[[str], str],
                context=None) -> ShieldResult:
        """One call: scan input (+context) -> call the LLM if allowed -> scan output.

        When context is given (RAG/tool content), it is scanned for indirect
        injection before the LLM is called; if it is blocked, the LLM is NEVER
        called.
        """
        # Inner scans are NOT emitted individually (_emit=False); protect emits a
        # SINGLE final decision, so one request = one audit record.
        inp = self.scan_input(prompt, _emit=False)
        if inp.action == "block":
            return self._emit(inp)  # the LLM was never called

        ctx = self.scan_context(context, _emit=False) if context is not None else None
        if ctx is not None and ctx.action == "block":
            return self._emit(ctx)  # poisoned context -> the LLM was never called

        raw = llm_fn(prompt)
        out = self.scan_output(raw, _emit=False)
        # if input/context was 'flag' and the output is clean, keep the flag
        upstream = [r for r in (inp, ctx) if r is not None and r.action == "flag"]
        if upstream and out.action == "allow":
            out.action = "flag"
            for r in upstream:
                out.detections = r.detections + out.detections
        return self._emit(out)

    def guard(self, llm_fn: Callable[[str], str]) -> Callable[[str], ShieldResult]:
        """Turn any LLM function into a guarded version of itself."""
        def wrapped(prompt: str, context=None) -> ShieldResult:
            return self.protect(prompt, llm_fn, context=context)
        return wrapped
