from pathlib import Path

from policyaware import Gateway, GatewayRequest, GuardrailResult
from policyaware.policy import PolicyEngine
from policyaware.models import Decision
from policyaware.cli import app
from typer.testing import CliRunner


class BlockingInputGuard:
    name = "blocking_input"

    def inspect_input(self, request: GatewayRequest) -> GuardrailResult:
        return GuardrailResult(
            name=self.name,
            allowed=False,
            reason="Input blocked by test guard.",
            score=0.0,
        )

    def inspect_output(self, request: GatewayRequest, output_text: str) -> GuardrailResult:
        return GuardrailResult(name=self.name)


class TransformingGuard:
    name = "transforming_guard"

    def inspect_input(self, request: GatewayRequest) -> GuardrailResult:
        return GuardrailResult(name=self.name, transformed_text="Summarize the safe ticket.")

    def inspect_output(self, request: GatewayRequest, output_text: str) -> GuardrailResult:
        return GuardrailResult(name=self.name, transformed_text="validated output")


class BlockingOutputGuard:
    name = "blocking_output"

    def inspect_input(self, request: GatewayRequest) -> GuardrailResult:
        return GuardrailResult(name=self.name)

    def inspect_output(self, request: GatewayRequest, output_text: str) -> GuardrailResult:
        return GuardrailResult(
            name=self.name,
            allowed=False,
            reason="Output blocked by test guard.",
            score=0.0,
        )


def _request() -> GatewayRequest:
    return GatewayRequest(
        tenant="acme",
        app="guard-test",
        user={"id": "u1", "role": "support_agent"},
        context={"region": "us", "risk": "low", "task_type": "summarization"},
        messages=[{"role": "user", "content": "Summarize this ticket."}],
    )


def test_gateway_blocks_input_guard_and_audits(tmp_path: Path) -> None:
    gateway = Gateway.from_policy_file("examples/policies/basic.yaml")
    gateway.audit_logger.path = tmp_path / "traces.jsonl"
    gateway.add_input_guard(BlockingInputGuard())

    response = gateway.chat(_request())

    assert response.policy.decision == Decision.DENY
    assert "GUARD.INPUT_BLOCKED" in response.policy.reason_codes
    assert response.metadata["guardrails"][0]["name"] == "blocking_input"
    assert (tmp_path / "traces.jsonl").exists()


def test_gateway_applies_input_and_output_guard_transforms() -> None:
    gateway = Gateway.from_policy_file("examples/policies/basic.yaml")
    gateway.add_guard(TransformingGuard())

    response = gateway.chat(_request())

    assert response.policy.decision == Decision.ALLOW
    assert response.content == "validated output"
    assert response.metadata["guardrails"]["input"][0]["transformed_text"] == "Summarize the safe ticket."
    assert response.metadata["guardrails"]["output"][0]["transformed_text"] == "validated output"


def test_gateway_blocks_output_guard() -> None:
    gateway = Gateway.from_policy_file("examples/policies/basic.yaml")
    gateway.add_output_guard(BlockingOutputGuard())

    response = gateway.chat(_request())

    assert response.policy.decision == Decision.DENY
    assert response.content == ""
    assert "GUARD.OUTPUT_BLOCKED" in response.policy.reason_codes
    assert response.metadata["guardrails"]["output"][0]["name"] == "blocking_output"


def test_gateway_loads_policy_driven_guards_from_registry() -> None:
    policy = {
        "id": "guard_policy",
        "schema_version": "0.2",
        "default": "deny",
        "guards": {
            "input": [
                {
                    "name": "transforming_guard",
                    "when": {"request.task_type": "summarization"},
                }
            ],
            "output": [
                {
                    "name": "transforming_guard",
                    "when": {"request.task_type": "summarization"},
                }
            ],
        },
        "rules": [
            {
                "name": "allow_support",
                "effect": "allow",
                "when": {
                    "user.role": "support_agent",
                    "request.risk": "low",
                },
            }
        ],
    }
    guard = TransformingGuard()
    gateway = Gateway(
        policy_engine=PolicyEngine(policy),
        guard_registry={guard.name: guard},
    )

    response = gateway.chat(_request())

    assert response.policy.decision == Decision.ALLOW
    assert response.content == "validated output"
    assert response.metadata["guardrails"]["input"][0]["name"] == "transforming_guard"
    assert response.metadata["guardrails"]["output"][0]["name"] == "transforming_guard"


def test_policy_driven_guard_when_clause_can_skip_guard() -> None:
    policy = {
        "id": "guard_policy",
        "schema_version": "0.2",
        "default": "deny",
        "guards": {
            "input": [
                {
                    "name": "blocking_input",
                    "when": {"request.task_type": "chatbot"},
                }
            ]
        },
        "rules": [
            {
                "name": "allow_support",
                "effect": "allow",
                "when": {
                    "user.role": "support_agent",
                    "request.risk": "low",
                },
            }
        ],
    }
    guard = BlockingInputGuard()
    gateway = Gateway(
        policy_engine=PolicyEngine(policy),
        guard_registry={guard.name: guard},
    )

    response = gateway.chat(_request())

    assert response.policy.decision == Decision.ALLOW
    assert response.metadata["guardrails"]["input"] == []


def test_guards_list_cli(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        """
id: guard_policy
schema_version: "0.2"
default: deny
guards:
  input:
    - name: nemo
      config_path: rails/
      when:
        request.task_type: chatbot
rules:
  - name: allow_support
    effect: allow
    when:
      user.role: support_agent
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["guards", "list", str(policy_file)])

    assert result.exit_code == 0
    assert "nemo" in result.output
    assert "rails/" in result.output
