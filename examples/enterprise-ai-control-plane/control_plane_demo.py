from __future__ import annotations

import json
from pathlib import Path

from policyaware import Gateway, GatewayRequest, ToolCallRequest, ToolPolicyEngine
from policyaware.integrations.microsoft_agt import to_agt_gateway_evidence, to_agt_tool_evidence


HERE = Path(__file__).resolve().parent


def main() -> None:
    gateway = Gateway.from_policy_file(HERE / "policyaware.yaml")

    request = GatewayRequest(
        tenant="acme",
        app="enterprise-support-agent",
        user={"id": "u_123", "role": "support_agent"},
        context={
            "region": "us",
            "risk": "medium",
            "task_type": "support",
            "domain": "customer_support",
            "autonomy": "agentic",
        },
        messages=[
            {
                "role": "user",
                "content": "Summarize this case and email jane@example.com if follow-up is needed.",
            }
        ],
    )
    response = gateway.chat(request)

    tool_engine = ToolPolicyEngine.from_file(HERE / "tool-governance.yaml")
    tool_decision = tool_engine.decide(
        ToolCallRequest(
            agent_id="support_agent_1",
            connector_id="crm",
            action="update_customer",
            arguments={"customer_id": "cust_123", "field": "email"},
            tenant="acme",
            user={"id": "u_123", "role": "support_agent"},
            context=request.context,
        )
    )

    gateway_evidence = to_agt_gateway_evidence(response)
    tool_evidence = to_agt_tool_evidence(
        tool_decision,
        agent_id="support_agent_1",
        tenant="acme",
        user={"id": "u_123", "role": "support_agent"},
        context=request.context,
        arguments={"customer_id": "cust_123", "field": "email"},
    )

    print("policy_decision=", response.policy.decision.value)
    print("risk_tier=", response.policy.risk_tier.value)
    print("route_model=", response.route.model.name if response.route else None)
    print("evals=", [result.name for result in response.evals])
    print("tool_decision=", tool_decision.decision.value)
    print("gateway_evidence_decision=", gateway_evidence["decision"])
    print("tool_evidence_decision=", tool_evidence["decision"])
    print("\ncontrol_plane_summary=")
    print(
        json.dumps(
            {
                "trace_id": response.trace_id,
                "policy": response.policy.decision.value,
                "risk": response.policy.risk_tier.value,
                "tool": tool_decision.decision.value,
                "reason_codes": response.policy.reason_codes,
                "tool_reason_codes": tool_decision.reason_codes,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
