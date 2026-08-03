from __future__ import annotations

import json
from pathlib import Path

from policyaware import ToolCallRequest, ToolPolicyEngine
from policyaware.integrations.microsoft_agt import to_agt_tool_evidence


HERE = Path(__file__).resolve().parent


def check_tool_action(action: str, arguments: dict[str, object]) -> dict[str, object]:
    engine = ToolPolicyEngine.from_file(HERE / "tool-governance.yaml")
    request = ToolCallRequest(
        agent_id="support_agent_1",
        connector_id="crm",
        action=action,
        arguments=arguments,
        tenant="acme",
        user={"id": "u_123", "role": "support_agent"},
        context={"region": "us", "risk": "medium", "task_type": "agent_tool_call"},
    )

    decision = engine.decide(request)
    return to_agt_tool_evidence(
        decision,
        agent_id=request.agent_id,
        tenant=request.tenant,
        user=request.user,
        context=request.context,
        arguments=request.arguments,
    )


if __name__ == "__main__":
    for action, arguments in [
        ("read_customer", {"customer_id": "cust_123"}),
        ("update_customer", {"customer_id": "cust_123", "field": "email"}),
        ("delete_customer", {"customer_id": "cust_123"}),
    ]:
        evidence = check_tool_action(action, arguments)
        print(f"{action}_decision={evidence['decision']}")
        print(f"{action}_policyaware_decision={evidence['policyaware_decision']}")
        print(f"{action}_approval_required={evidence['enforcement']['approval_required']}")

    print("\nexample_evidence_json=")
    print(json.dumps(check_tool_action("update_customer", {"customer_id": "cust_123"}), indent=2))
