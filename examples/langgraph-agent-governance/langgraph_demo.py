from __future__ import annotations

from pathlib import Path

from policyaware import PolicyAwareNodeGuard


HERE = Path(__file__).resolve().parent


guard = PolicyAwareNodeGuard(
    config=HERE / "policyaware.yaml",
    tool_policy=HERE / "tool-governance.yaml",
    tenant="acme",
    app="support-langgraph",
    default_user={"id": "u_123", "role": "support_agent"},
)


def support_node(state: dict) -> dict:
    return {"messages": [{"role": "assistant", "content": "Customer record summarized safely."}]}


guarded_support_node = guard.guard_node(support_node)


if __name__ == "__main__":
    safe_state = {
        "context": {"region": "us", "risk": "low", "task_type": "support"},
        "messages": [{"role": "user", "content": "Summarize the open support case."}],
    }
    blocked_state = {
        "context": {"region": "us", "risk": "low", "task_type": "support"},
        "messages": [{"role": "user", "content": "Use api_key_abcdefghijklmnopqrstuvwxyz"}],
    }

    print("safe_node_output=", guarded_support_node(safe_state))
    print("blocked_node_output=", guarded_support_node(blocked_state))

    tool_decision = guard.check_tool_call(
        agent_id="support_agent_1",
        connector_id="crm",
        action="update_customer",
        arguments={"customer_id": "cust_123", "field": "email"},
        user={"id": "u_123", "role": "support_agent"},
    )
    print("tool_decision=", tool_decision.decision.value)
    print("tool_approval_required=", tool_decision.approval_required)
