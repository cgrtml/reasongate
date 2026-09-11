"""reasongate — a model-agnostic, explainable security gate for LLM apps."""
from reasongate.agent_gate import GateDecision, ToolGate, ToolPolicy, GateSession
from reasongate.policy_gate import DeploymentPolicy, PolicyGate, TermJudge
from reasongate.audit import AuditHook, file_sink, log_sink
from reasongate.shield import Shield
from reasongate.types import (AUDIT_SCHEMA_VERSION, Detection, Segment,
                              ShieldResult)

__all__ = ["Shield", "Detection", "Segment", "ShieldResult",
           "AuditHook", "log_sink", "file_sink", "AUDIT_SCHEMA_VERSION",
           "ToolGate", "ToolPolicy", "GateDecision", "GateSession",
           "PolicyGate", "DeploymentPolicy", "TermJudge"]
__version__ = "0.3.0"
