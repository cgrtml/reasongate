"""The destination-spelling table, run as a test.

`eval/canon_probe.py` enumerates the ways one destination can be written and what the
gate should do with each: stop the ones that reach the same place, allow the ones that
do not. Four of those rows were live defects when the file was written. Importing the
table here rather than restating it keeps one copy of the claims, so a case added to the
probe is a case CI runs.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "eval"))

import canon_probe as probe                                          # noqa: E402


def test_controls_hold():
    broken = [c["control"] for c in probe.controls() if not c["ok"]]
    assert not broken, f"the harness itself is wrong: {broken}"


def test_every_rewrite_of_a_destination():
    rows = probe.run(probe.REWRITES, probe.taint, "rewrite")
    missed = [r["case"] for r in rows if not r["ok"] and r["should_stop"]]
    over = [r["case"] for r in rows if not r["ok"] and not r["should_stop"]]
    assert not missed, f"the same destination, not recognised: {missed}"
    assert not over, f"a different destination, blocked anyway: {over}"


def test_the_allowlist_means_what_it_says():
    rows = probe.run(probe.ALLOWLIST, probe.vouch, "allowlist")
    claimed = [r["case"] for r in rows if not r["ok"] and r["should_stop"]]
    refused = [r["case"] for r in rows if not r["ok"] and not r["should_stop"]]
    assert not claimed, f"an entry matched more than the deployment allowed: {claimed}"
    assert not refused, f"an allowed destination was stopped: {refused}"
