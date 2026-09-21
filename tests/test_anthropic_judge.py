"""The reference judge, exercised with a fake client: no network, no SDK required."""
import json
from types import SimpleNamespace

from reasongate import DeploymentPolicy, PolicyGate
from reasongate.judges import AnthropicJudge

POLICY = DeploymentPolicy(name="newsroom assistant",
                          forbids=("partisan advocacy or campaigning",
                                   "defaming a person or organisation"))


class FakeMessages:
    def __init__(self, payload, stop_reason="end_turn"):
        self.payload, self.stop_reason, self.calls = payload, stop_reason, []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(stop_reason=self.stop_reason,
                               content=[SimpleNamespace(type="text", text=json.dumps(self.payload))])


def _client(payload, stop_reason="end_turn"):
    return SimpleNamespace(messages=FakeMessages(payload, stop_reason))


def test_conflict_carries_the_rule_into_the_evidence():
    judge = AnthropicJudge(client=_client({"conflicts": True, "rule": 1, "reason": "asks for a campaign manifesto"}))
    conflicts, reason, evidence = judge("Write a manifesto for the re-election of X", POLICY)
    assert conflicts and "manifesto" in reason
    assert evidence == ["rule 1: partisan advocacy or campaigning"]


def test_request_is_data_and_policy_is_the_system_instruction():
    fake = _client({"conflicts": False, "rule": None, "reason": "ordinary question"})
    AnthropicJudge(client=fake)("What is the weather in Berlin?", POLICY)
    call = fake.messages.calls[0]
    assert "<request>" in call["messages"][0]["content"]
    assert "partisan advocacy" in call["system"][0]["text"]
    assert call["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert call["output_config"]["format"]["type"] == "json_schema"
    assert "temperature" not in call


def test_refusal_is_not_a_clearance():
    judge = AnthropicJudge(client=_client({"conflicts": False, "rule": None, "reason": ""}, stop_reason="refusal"))
    decision = PolicyGate(POLICY, judge=judge).review("anything")
    assert decision.allowed
    assert any("could not be evaluated" in d.reason for d in decision.detections)


def test_policy_gate_blocks_on_a_judged_conflict_when_told_to():
    judge = AnthropicJudge(client=_client({"conflicts": True, "rule": 2, "reason": "defames the editor"}))
    decision = PolicyGate(POLICY, judge=judge, block_on_conflict=True).review("Say the editor is a criminal")
    assert decision.action == "block"
    assert any("rule 2" in m for d in decision.detections for m in d.matches)


def test_effort_is_sent_only_when_asked_for():
    """Haiku 4.5 rejects `effort` with a 400; the default omits it."""
    fake = _client({"conflicts": False, "rule": None, "reason": "ok"})
    AnthropicJudge(client=fake)("hello", POLICY)
    assert "effort" not in fake.messages.calls[0]["output_config"]
    fake2 = _client({"conflicts": False, "rule": None, "reason": "ok"})
    AnthropicJudge(client=fake2, effort="low")("hello", POLICY)
    assert fake2.messages.calls[0]["output_config"]["effort"] == "low"


def test_truncated_answer_is_reported_not_parsed():
    judge = AnthropicJudge(client=_client({"conflicts": True, "rule": 1, "reason": "cut"}, stop_reason="max_tokens"))
    decision = PolicyGate(POLICY, judge=judge).review("anything")
    assert decision.allowed
    assert any("could not be evaluated" in d.reason for d in decision.detections)
