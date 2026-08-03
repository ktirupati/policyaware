from __future__ import annotations

from pathlib import Path

from policyaware import Gateway, GatewayRequest, PolicyAwareSidecar, SessionStateMonitor
from policyaware.tools import ToolPolicyEngine


ROOT = Path(__file__).resolve().parents[1]


def test_gateway_blocks_cumulative_sensitive_data_in_session() -> None:
    gateway = Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml")
    gateway.session_monitor = SessionStateMonitor(max_sensitive_findings_per_session=1)

    first = gateway.chat(_request("Email jane@example.com", session_id="case-123"))
    second = gateway.chat(_request("Call 212-555-7890", session_id="case-123"))

    assert first.policy.decision.value in {"allow", "conditional_allow"}
    assert second.policy.decision.value == "deny"
    assert "SESSION.CUMULATIVE_SENSITIVE_DATA" in second.policy.reason_codes
    assert second.metadata["session"]["sensitive_findings"] >= 2


def test_sidecar_blocks_repeated_tool_calls_in_session() -> None:
    gateway = Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml")
    gateway.session_monitor = SessionStateMonitor(max_tool_calls_per_session=2)
    sidecar = PolicyAwareSidecar(
        gateway,
        ToolPolicyEngine.from_file(ROOT / "examples" / "policies" / "tool-governance.yaml"),
        session_monitor=gateway.session_monitor,
    )
    body = {
        "agent_id": "code_assistant",
        "connector_id": "github",
        "action": "read_file",
        "user": {"role": "developer"},
        "context": {"session_id": "agent-session-1"},
    }

    first_status, first = sidecar.handle("POST", "/v1/tool/check", body)
    second_status, second = sidecar.handle("POST", "/v1/tool/check", body)
    third_status, third = sidecar.handle("POST", "/v1/tool/check", body)

    assert first_status == 200
    assert second_status == 200
    assert third_status == 200
    assert first["decision"] == "allow"
    assert second["decision"] == "allow"
    assert third["decision"] == "deny"
    assert "SESSION.TOOL_CALL_LIMIT_EXCEEDED" in third["reason_codes"]


def _request(prompt: str, *, session_id: str) -> GatewayRequest:
    return GatewayRequest(
        tenant="acme",
        app="session-test",
        user={"id": "u_123", "role": "support_agent"},
        context={"region": "us", "risk": "low", "task_type": "support", "session_id": session_id},
        messages=[{"role": "user", "content": prompt}],
    )

