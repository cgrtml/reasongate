"""Plugin registry — separately-installed packages (e.g. the enterprise add-on)
contribute detectors via entry points, without the core depending on them.

This is the public API contract the enterprise package leans on:

- Detectors implement ``reasongate.detectors.base.Detector`` (``.scan(text) ->
  Detection``, ``.name``, ``.stage`` in {"input", "context", "output"}) and are
  exposed under the entry-point group ``reasongate.detectors``.
- Segment-aware provenance providers use the group ``reasongate.provenance``
  (they expose ``.scan_segment(Segment) -> Detection`` and a ``.name``).

If nothing is installed the core runs rule-only — **silently, never an error**.
A failing plugin is logged and skipped; it can never break the gate.
"""
from __future__ import annotations

import logging
from importlib.metadata import entry_points

logger = logging.getLogger(__name__)

DETECTOR_GROUP = "reasongate.detectors"
PROVENANCE_GROUP = "reasongate.provenance"


def _iter(group):
    """Iterate entry points for a group, across Python 3.9 and 3.10+ APIs."""
    try:
        eps = entry_points()
        if hasattr(eps, "select"):          # 3.10+
            return list(eps.select(group=group))
        return list(eps.get(group, []))     # 3.9 (dict-like)
    except Exception as exc:                # pragma: no cover - defensive
        logger.warning("entry-point discovery failed: %s", exc)
        return []


def load_plugin_detectors():
    """Instantiate every detector registered under ``reasongate.detectors``.
    A plugin that fails to load/instantiate is skipped (logged), not raised."""
    out = []
    for ep in _iter(DETECTOR_GROUP):
        try:
            out.append(ep.load()())
            logger.info("loaded plugin detector: %s", ep.name)
        except Exception as exc:
            logger.warning("plugin detector %r failed to load: %s", ep.name, exc)
    return out


def load_provenance(**kwargs):
    """Return the first available provenance provider (or None if none installed)."""
    for ep in _iter(PROVENANCE_GROUP):
        try:
            return ep.load()(**kwargs)
        except Exception as exc:
            logger.warning("provenance plugin %r failed to load: %s", ep.name, exc)
    return None
