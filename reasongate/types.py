"""Core data types.

Every detection (Detection) carries a REASON — that is the foundation of the
gate being explainable rather than a black box. Every decision (ShieldResult)
also converts to a machine-readable, auditable record (to_dict / to_json) with
a unique decision_id, a UTC timestamp and a schema version, so a SOC/SIEM or an
auditor can ingest the decision as-is.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

# Audit record schema version — bumped when the record format changes, so
# downstream consumers (SIEM, archive) know which version they are reading.
AUDIT_SCHEMA_VERSION = "1.0"


def _new_decision_id() -> str:
    return uuid.uuid4().hex


def _now_epoch() -> float:
    return datetime.now(timezone.utc).timestamp()


@dataclass
class Detection:
    detector: str            # detector name (e.g. "injection")
    triggered: bool          # was its threshold crossed
    score: float             # 0..1 risk score
    reason: str              # human-readable justification ("why")
    matches: List[str] = field(default_factory=list)  # the evidence that fired

    def to_dict(self) -> dict:
        """Machine-readable detection record (for audit/SIEM)."""
        return {
            "detector": self.detector,
            "triggered": bool(self.triggered),
            "score": round(float(self.score), 4),
            "reason": self.reason,
            "matches": list(self.matches),
        }


@dataclass
class Segment:
    """A piece of retrieved/tool-produced content plus its PROVENANCE metadata.

    For provenance-aware scan_context: whether an instruction came from the USER
    or from RETRIEVED content is decided by its ORIGIN, not by its text (see
    _notes/spec_17_provenance.md). Backward compatible: scan_context also accepts
    plain str, in which case provenance is OFF (identical to the old behavior).
    """
    text: str
    source: str = "retrieved"      # "user" | "retrieved" | "tool" | "web" | "file"
    trust: str = "untrusted"       # "trusted" | "untrusted"
    domain: Optional[str] = None   # origin (e.g. "wikipedia.org", "inbox", "vendor-x")


@dataclass
class ShieldResult:
    action: str              # "allow" | "flag" | "block"
    stage: str               # "input" | "output" | "context"
    detections: List[Detection]
    output: Optional[str] = None   # the model's (scanned) output, when not blocked
    # --- Audit fields: every decision is uniquely identified and timestamped ---
    decision_id: str = field(default_factory=_new_decision_id)
    timestamp: float = field(default_factory=_now_epoch)  # UTC epoch seconds
    # The layers that produced this decision (e.g. ["injection","normalization"]
    # vs +["ml_injection","provenance"]). Shows up here when the enterprise
    # add-on is installed.
    layers: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.action != "block"

    @property
    def risk_score(self) -> float:
        """The highest single-detector score behind the decision (0 = no signal)."""
        return round(max((d.score for d in self.detections), default=0.0), 4)

    @property
    def triggered_detectors(self) -> List[str]:
        """Names of the detectors that crossed their threshold and drove the decision."""
        return [d.detector for d in self.detections if d.triggered]

    def to_dict(self, *, include_output: bool = True) -> dict:
        """Machine-readable, SIEM-friendly audit record.

        include_output=False: the model output is kept out of the record, for
        deployments that must not let sensitive content reach the audit trail."""
        rec = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "decision_id": self.decision_id,
            "timestamp": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
            "stage": self.stage,
            "action": self.action,
            "allowed": self.allowed,
            "risk_score": self.risk_score,
            "layers": self.layers,
            "triggered_detectors": self.triggered_detectors,
            "detections": [d.to_dict() for d in self.detections],
        }
        if include_output:
            rec["output"] = self.output
        return rec

    def to_json(self, *, include_output: bool = True, **json_kwargs) -> str:
        """JSON string of to_dict. Non-ASCII content is NOT escaped
        (ensure_ascii=False) so quoted evidence stays readable in the log."""
        json_kwargs.setdefault("ensure_ascii", False)
        return json.dumps(self.to_dict(include_output=include_output), **json_kwargs)

    def explain(self) -> str:
        """Human-readable summary: what was done and WHY."""
        head = {"allow": "ALLOWED", "flag": "FLAGGED", "block": "BLOCKED"}[self.action]
        lines = [f"[{self.stage}] {head}"]
        for d in self.detections:
            mark = "✗" if d.triggered else "·"
            lines.append(f"  {mark} {d.detector} (score={d.score:.2f}): {d.reason}")
            if d.triggered and d.matches:
                lines.append(f"      evidence: {', '.join(d.matches[:5])}")
        return "\n".join(lines)
