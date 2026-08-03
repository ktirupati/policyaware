# Microsoft AGT-Style Interop

PolicyAware can export policy, tool-governance, gateway, and audit decisions as Microsoft Agent Governance Toolkit-style evidence JSON.

This is useful for teams that want PolicyAware to stay vendor-neutral while still producing structured evidence objects for broader enterprise agent governance workflows.

Important: this module is dependency-free and schema-labeled as PolicyAware interop. It is not an official Microsoft-owned wire contract.

## When To Use It

Use this integration when you need to:

- govern MCP-style or agent tool calls with PolicyAware
- export allow, deny, and approval-required decisions as normalized evidence
- preserve reason codes, matched policy rules, tenant, user, agent, and action context
- feed governance evidence into downstream review, audit, or security reporting systems

## Install

```bash
pip install policyaware
```

No extra package is required.

## Tool Governance YAML

```yaml
default: deny

connectors:
  - id: crm
    description: CRM connector used by an enterprise support agent.
    actions:
      read_customer:
        effect: allow
        when:
          user.role_in: ["support_agent", "manager"]
        limits:
          requests_per_minute: 60

      update_customer:
        effect: require_approval
        when:
          user.role_in: ["support_agent", "manager"]
        limits:
          requests_per_minute: 10

      delete_customer:
        effect: deny
        when:
          user.role_in: ["support_agent", "manager"]
```

## Code Example

```python
from policyaware import ToolCallRequest, ToolPolicyEngine
from policyaware.integrations.microsoft_agt import to_agt_tool_evidence

engine = ToolPolicyEngine.from_file("tool-governance.yaml")

request = ToolCallRequest(
    agent_id="support_agent_1",
    connector_id="crm",
    action="update_customer",
    arguments={"customer_id": "cust_123", "field": "email"},
    tenant="acme",
    user={"id": "u_123", "role": "support_agent"},
    context={"region": "us", "risk": "medium"},
)

decision = engine.decide(request)
evidence = to_agt_tool_evidence(
    decision,
    agent_id=request.agent_id,
    tenant=request.tenant,
    user=request.user,
    context=request.context,
    arguments=request.arguments,
)

print(evidence["decision"])
print(evidence["policyaware_decision"])
print(evidence["enforcement"]["approval_required"])
```

Expected output:

```text
review
require_approval
True
```

## API Reference

| API | Purpose |
| --- | --- |
| `to_agt_decision(decision)` | Converts a `PolicyDecision` or `ToolDecision` into AGT-style evidence JSON. |
| `to_agt_tool_evidence(decision, ...)` | Adds agent, tenant, user, connector, action, arguments, limits, and approval context. |
| `to_agt_gateway_evidence(response)` | Converts a full `GatewayResponse` into request/model/risk/eval evidence. |
| `to_agt_audit_evidence(trace)` | Converts an `AuditTrace` or audit-trace dictionary into evidence JSON. |

## Evidence Shape

```json
{
  "schema": "policyaware.microsoft_agt.evidence.v1",
  "evidence_id": "agt_ev_...",
  "created_at": "2026-08-03T14:00:00+00:00",
  "decision": "review",
  "policyaware_decision": "require_approval",
  "enforcement": {
    "allowed": false,
    "approval_required": true,
    "blocked": false
  },
  "reason_codes": ["TOOL.APPROVAL_REQUIRED"],
  "matched_rules": ["crm.update_customer"],
  "subject": {
    "type": "agent_tool_call",
    "agent_id": "support_agent_1",
    "tenant": "acme",
    "user": {"id": "u_123", "role": "support_agent"}
  },
  "action": {
    "connector_id": "crm",
    "name": "update_customer",
    "arguments": {"customer_id": "cust_123"},
    "context": {"region": "us", "risk": "medium"}
  }
}
```

## How This Fits With Microsoft AGT

Microsoft Agent Governance Toolkit focuses on runtime security governance for autonomous agents, including zero-trust identity, sandboxing, reliability, and agentic threat controls.

PolicyAware focuses on vendor-neutral policy enforcement across prompts, context, RAG, model routing, MCP/tool calls, evals, audit traces, and local code scans.

The recommended integration pattern is to keep PolicyAware as the AI policy gateway and export PolicyAware evidence into enterprise governance systems when your organization standardizes reporting around Microsoft AGT-style workflows.

## Runnable Example

See:

```text
examples/microsoft-agt-interop/
```
