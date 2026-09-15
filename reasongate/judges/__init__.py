"""Reference judges for `PolicyGate`.

The gate itself ships no model. A judge is what turns a prose policy ("no partisan
advocacy") into a verdict on a request, and that needs one. This package holds a reference
implementation, off by default and installed separately:

    pip install "reasongate[judge]"

    from reasongate import PolicyGate, DeploymentPolicy
    from reasongate.judges import AnthropicJudge
    gate = PolicyGate(policy, judge=AnthropicJudge())

Read `AnthropicJudge`'s docstring before relying on it: a model judge reads the attacker's
text and is itself an injection target; its verdict is one signal, not a capability
boundary. Measured numbers are in RESULTS.md.
"""
from reasongate.judges.anthropic_judge import AnthropicJudge

__all__ = ["AnthropicJudge"]
