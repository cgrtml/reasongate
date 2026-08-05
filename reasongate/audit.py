"""Audit emission — structured, SIEM-friendly, zero-dependency.

Every decision (ShieldResult) converts to an audit record (see types.to_dict).
This module provides the lightweight hooks that push those records to a 'sink'.
The default sink is Python's standard logging (the "reasongate.audit" logger),
so there is no extra dependency and records flow straight into existing log
infrastructure (journald, ELK, a Splunk forwarder).

Design principle: THE AUDIT TRAIL NEVER BREAKS THE GATE. If an audit hook
raises, the security decision is still returned; the error is swallowed and
reported on a separate channel.

Enterprise sinks (tamper-evident hash chain, direct SIEM connectors, retention
policy) are built on top of this hook in a separate (private) layer.
"""
from __future__ import annotations

import logging
from typing import Callable, TextIO

from reasongate.types import ShieldResult

# Dedicated logger for decision records. The application attaches whatever
# handler it wants to it.
audit_logger = logging.getLogger("reasongate.audit")

# Separate logger for hook failures (kept off the audit channel itself).
_internal_logger = logging.getLogger("reasongate")

# An audit hook: takes the decision and emits it as a side effect (no return).
AuditHook = Callable[[ShieldResult], None]


def log_sink(result: ShieldResult) -> None:
    """Default hook: writes the decision as single-line JSON to 'reasongate.audit'."""
    audit_logger.info(result.to_json())


def file_sink(path: str, *, include_output: bool = True) -> AuditHook:
    """Hook that appends decisions to a file as JSON-Lines (one decision per line).

    The standard format for SIEM ingestion and archival. The file is kept open
    in append mode."""
    fh: TextIO = open(path, "a", encoding="utf-8")

    def _sink(result: ShieldResult) -> None:
        fh.write(result.to_json(include_output=include_output) + "\n")
        fh.flush()

    return _sink


def safe_emit(hook: AuditHook, result: ShieldResult) -> None:
    """Call the hook; swallow any error and log it on a separate channel.
    Emitting an audit record must never, under any circumstance, break the
    security decision."""
    try:
        hook(result)
    except Exception:  # pragma: no cover - defensive
        _internal_logger.exception("audit hook failed (the security decision was not affected)")
