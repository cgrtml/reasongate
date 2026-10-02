"""Does the shape this gate is built for exist outside AgentDojo?

The first limitation this project reports about itself is that twenty-three of the
twenty-six replayable AgentDojo injection tasks name their destination in the injected
text, so a defence that compares destinations against untrusted content is being measured
on the shape it was built for. That is a fair objection and it has an answer that costs
nothing: count the same thing on a corpus nobody here chose.

InjecAgent (Zhan et al., 2024) is an independent benchmark of indirect prompt injection
against tool-using agents. It ships, for every case, the user's tool call, the poisoned
tool response with the injection embedded verbatim, and the attacker's instruction. It
does not ship the attacker's argument values, so it cannot drive the model-free replay in
`eval/agentdojo_gate.py`, and this script does not pretend otherwise. What it measures is
narrower and is a property of the corpus rather than of the gate: how often the attacker's
objective requires a value the agent has to copy out of the injected text.

Two readings, because the gate has two paths and they do not agree:

- `content`: the token would be traced inside a composed message body, which is the
  gate's own `_CONTENT_TOKEN` rule. It is deliberately narrow and misses an identifier
  like `guest_amy01`.
- `destination`: the instruction names any value that is not ordinary prose, which is
  what a destination argument check would compare. This is the wider and more relevant
  of the two, because a destination argument is checked whatever its shape.

    python eval/injecagent_shape.py              # fetches the data on first run
    python eval/injecagent_shape.py --json out.json

No model, no API key, a few seconds. Needs network on the first run only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from reasongate.agent_gate import _CONTENT_TOKEN            # noqa: E402

RAW = "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/"
CACHE = os.path.join(HERE, "data", "injecagent")
SETS = [("direct harm", "test_cases_dh_base.json"),
        ("data stealing", "test_cases_ds_base.json")]

# A value the attacker's instruction names rather than describes: anything with a digit or
# an at sign in it that is at least four characters long. Ordinary English words have
# neither, so this is a cheap stand-in for "a value, not prose", and the samples it picks
# out are addresses, account numbers, payee codes and account ids.
#
# It undercounts on purpose rather than by accident. A destination spelled only in letters
# is missed: "move the files to the '.hidden' folder" names a destination this rule does
# not see, while the gate itself would compare it like any other argument value. Every
# figure below is therefore a lower bound, which is the direction to be wrong in.
NAMED_VALUE = re.compile(r"\b(?=[\w.@+-]*[\d@])[\w.@+-]{4,}\b")


def fetch(name: str) -> list:
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, name)
    if not os.path.exists(path):
        with urllib.request.urlopen(RAW + name, timeout=120) as r:
            open(path, "wb").write(r.read())
    return json.load(open(path, encoding="utf-8"))


def content_tokens(text: str) -> list:
    return [t for t in (m.group(0).rstrip(".,;:)!?\"'") for m in _CONTENT_TOKEN.finditer(text))
            if len(t) >= 4]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    rows, examples = [], []
    for label, fname in SETS:
        cases = fetch(fname)
        per_instruction = {}
        for c in cases:
            per_instruction[c["Attacker Instruction"]] = per_instruction.get(
                c["Attacker Instruction"], 0) + 1
        narrow = wide = narrow_cases = wide_cases = 0
        for instruction, n in per_instruction.items():
            has_content = bool(content_tokens(instruction))
            has_value = bool(NAMED_VALUE.findall(instruction))
            narrow += has_content
            wide += has_value
            narrow_cases += n * has_content
            wide_cases += n * has_value
            if not has_value and len(examples) < 4:
                examples.append((label, instruction))
        rows.append({"set": label, "instructions": len(per_instruction), "cases": len(cases),
                     "content_instructions": narrow, "value_instructions": wide,
                     "content_cases": narrow_cases, "value_cases": wide_cases})

    print("How often an attacker in InjecAgent names a value the agent must copy out of\n"
          "the injected text, which is the shape a destination check can reach.\n")
    print(f"{'set':16}{'instructions':>13}{'cases':>8}{'names a value':>16}{'of cases':>12}")
    for r in rows:
        print(f"{r['set']:16}{r['instructions']:>13}{r['cases']:>8}"
              f"{r['value_instructions']:>10} / {r['instructions']:<3}"
              f"{r['value_cases']/r['cases']*100:>11.1f}%")
    tc = sum(r["cases"] for r in rows)
    tv = sum(r["value_cases"] for r in rows)
    ti = sum(r["instructions"] for r in rows)
    print(f"\n{tv} of {tc} cases ({tv/tc*100:.1f}%), built from {ti} distinct attacker "
          f"instructions.\nAgentDojo, for comparison: 23 of 26 replayable injection tasks.")
    print("\nRead the two columns apart. The case count is the corpus as it is distributed,\n"
          "and the instruction count is how much of it is independent: each instruction is\n"
          "paired with many user tasks, so the cases are not 1054 separate attacks.")
    print("\nAnd read the figure as a lower bound. The rule looks for a digit or an at sign,\n"
          "so a destination written only in letters, a folder named '.hidden' for instance,\n"
          "counts as naming nothing here while the gate would compare it like any value.")
    if examples:
        print("\nAttacks that name nothing, which a destination check cannot reach:")
        for label, text in examples:
            print(f"  [{label}] {text[:88]}")

    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"rows": rows, "total_cases": tc, "cases_naming_a_value": tv}, fh, indent=1)
        print(f"\nwrote {a.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
