from __future__ import annotations

from pathlib import Path
from typer.testing import CliRunner

from policyaware import PolicyAwareNodeGuard
from policyaware.cli import app


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "examples" / "policies" / "basic.yaml"
TOOL_POLICY = ROOT / "examples" / "policies" / "tool-governance.yaml"


def test_langgraph_node_guard_allows_safe_state() -> None:
    guard = PolicyAwareNodeGuard(config=POLICY)

    result = guard.check_state(
        {
            "tenant": "acme",
            "user": {"id": "u_1", "role": "support_agent"},
            "context": {"region": "us", "risk": "low", "task_type": "support"},
            "messages": [{"role": "user", "content": "Summarize this ticket."}],
        }
    )

    assert result.allowed is True
    assert result.state_update["policyaware"]["decision"] in {"allow", "conditional_allow"}


def test_langgraph_node_guard_blocks_denied_state() -> None:
    guard = PolicyAwareNodeGuard(config=POLICY)

    wrapped = guard.guard_node(lambda state: {"result": "node executed"})
    output = wrapped(
        {
            "tenant": "acme",
            "user": {"id": "u_1", "role": "support_agent"},
            "context": {"region": "us", "risk": "low", "task_type": "support"},
            "messages": [{"role": "user", "content": "Use api_key_abcdefghijklmnopqrstuvwxyz"}],
        }
    )

    assert output["policyaware"]["allowed"] is False
    assert output["policyaware"]["decision"] == "deny"
    assert output["messages"][0]["content"].startswith("Request blocked")


def test_langgraph_tool_guard_uses_tool_policy() -> None:
    guard = PolicyAwareNodeGuard(config=POLICY, tool_policy=TOOL_POLICY)

    decision = guard.check_tool_call(
        agent_id="code_assistant",
        connector_id="github",
        action="create_pr",
        arguments={"title": "Update docs"},
        user={"role": "developer"},
    )

    assert decision.decision.value in {"allow", "require_approval"}
    assert decision.connector_id == "github"


def test_integrations_list_cli() -> None:
    result = CliRunner().invoke(app, ["integrations", "list"])

    assert result.exit_code == 0
    assert "LangGraph" in result.output
    assert "PolicyAware Integrations" in result.output


def test_integrations_list_cli_json() -> None:
    result = CliRunner().invoke(app, ["integrations", "list", "--json"])

    assert result.exit_code == 0
    assert '"name": "LangGraph"' in result.output
    assert '"name": "Microsoft AGT-style evidence"' in result.output
    assert '"extra": "guardrails"' in result.output
