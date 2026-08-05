"""Guard for evaluation scripts that need the enterprise ML add-on.

Since 0.2.0 the ML detector, its trained model and the provenance detector live
in the separately-licensed `reasongate-enterprise` add-on (see CHANGELOG). Any
script here that trains, loads or scores with that model therefore cannot run
against a plain checkout of this repository.

Rather than dying on an ImportError or a FileNotFoundError halfway through a
run, those scripts call `require_addon()` up front and exit with an explanation
of what is missing and what still works without it.

The rule-core benchmarks — `eval/public_bench.py` (over-defense) and
`eval/adversarial.py` (evasion) — have no such dependency: they are offline and
run against this repository alone. The methodology, thresholds and harness for
everything else stay here so the numbers in RESULTS.md remain auditable.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MODELS = os.path.join(ROOT, "reasongate", "models")

_MESSAGE = """\
This script needs the enterprise ML add-on, which is not installed.

  missing: {what}

The ML detector, the trained model and the provenance detector moved out of the
open core in 0.2.0; they ship in the separately-licensed `reasongate-enterprise`
package. This repository keeps the methodology, the thresholds and the harness,
so the numbers in RESULTS.md stay auditable — but the model itself is not here.

Runs against this repository alone (no add-on, no API key, fully offline):
  python eval/public_bench.py    # over-defense on NotInject (339 benign)
  python eval/adversarial.py     # evasion robustness of the rule core
"""


def has_addon() -> bool:
    """True when the ML add-on (its detector module and model directory) is present."""
    try:
        import importlib
        importlib.import_module("reasongate.detectors.ml_injection")
    except Exception:
        return False
    return os.path.isdir(MODELS)


def require_addon(what: str = "reasongate.detectors.ml_injection + reasongate/models/") -> None:
    """Exit with a clear explanation when the ML add-on is unavailable."""
    if not has_addon():
        print(_MESSAGE.format(what=what), file=sys.stderr)
        raise SystemExit(2)
