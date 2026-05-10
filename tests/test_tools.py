from policyaware.models import Decision, ToolCallRequest
from policyaware.tools import ToolPolicyEngine


def test_tool_action_requires_approval() -> None:
    engine = ToolPolicyEngine.from_file("examples/policies/tool-governance.yaml")

    decision = engine.decide(
        ToolCallRequest(
            agent_id="code_assistant",
            connector_id="github",
            action="create_pr",
            user={"role": "developer"},
        )
    )

    assert decision.decision == Decision.REQUIRE_APPROVAL
    assert decision.approval_required is True


def test_tool_action_denied_when_condition_fails() -> None:
    engine = ToolPolicyEngine.from_file("examples/policies/tool-governance.yaml")

    decision = engine.decide(
        ToolCallRequest(
            agent_id="code_assistant",
            connector_id="snowflake",
            action="query",
            user={"role": "analyst"},
            arguments={"database": "payroll"},
        )
    )

    assert decision.decision == Decision.DENY

