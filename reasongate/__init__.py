"""reasongate — model-bagimsiz, aciklanabilir LLM guvenlik kalkani."""
from reasongate.agent_gate import GateDecision, ToolGate, ToolPolicy
from reasongate.audit import AuditHook, file_sink, log_sink
from reasongate.shield import Shield
from reasongate.types import (AUDIT_SCHEMA_VERSION, Detection, Segment,
                              ShieldResult)

__all__ = ["Shield", "Detection", "Segment", "ShieldResult",
           "AuditHook", "log_sink", "file_sink", "AUDIT_SCHEMA_VERSION",
           "ToolGate", "ToolPolicy", "GateDecision"]
__version__ = "0.2.0"
