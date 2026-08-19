# MCP Tool Permission Gateway

PolicyAware governs MCP-style tool calls by checking agent identity, connector name, action name, request arguments, user role, tenant, region, budgets, and approval requirements before a tool executes.

This page is for developers searching for intercept model context protocol MCP tools in Python, MCP tool permission gateway, or zero-trust tool governance for AI agents.

## Install

```bash
pip install policyaware
```

## Copy-Paste Tool Governance Policy

```yaml
name: mcp-tool-permission-policy
version: 1
default_decision: deny

tools:
  default_decision: deny
  connectors:
    github:
      actions:
        read_issue:
          allowed_roles: ["developer", "security_engineer", "admin"]
        create_pr:
          allowed_roles: ["developer", "admin"]
          require_approval: true
        delete_repo:
          allowed_roles: []
          deny: true
    database:
      actions:
        select:
          allowed_roles: ["analyst", "admin"]
          max_rows: 1000
        update:
          allowed_roles: ["admin"]
          require_approval: true
        drop_table:
          allowed_roles: []
          deny: true

budgets:
  tools:
    max_calls_per_request: 5
    max_calls_per_session: 25
```

## Python Example

```python
from policyaware.tools import ToolCallRequest, ToolPolicyEngine

engine = ToolPolicyEngine.from_policy_file("tool-governance.yaml")

decision = engine.decide(
    ToolCallRequest(
        agent_id="support-agent-1",
        user={"id": "u_123", "role": "developer"},
        tenant="acme",
        region="us",
        connector="github",
        action="create_pr",
        arguments={"repo": "acme/app", "title": "Fix policy regression"},
    )
)

print(decision.decision)
print(decision.reason_codes)
print(decision.requires_approval)
```

## CLI Example

```bash
policyaware tools check tool-governance.yaml \
  --agent support-agent-1 \
  --connector github \
  --action create_pr \
  --role developer
```

## Typical Decisions

| Tool Call | Result |
| --- | --- |
| `github.read_issue` by developer | Allow |
| `github.create_pr` by developer | Require approval |
| `github.delete_repo` by any role | Deny |
| `database.drop_table` by agent | Deny |

## Governance Pattern

Use PolicyAware in front of tool execution:

1. Register tools and connectors.
2. Require explicit allow rules for actions.
3. Deny destructive actions by default.
4. Require approval for writes, deletes, payments, deployments, and external sends.
5. Log every tool decision with trace ID and reason codes.

## Related Documentation

- [Tool Governance](../capabilities/tool-governance.md)
- [Policy Composition](../policy-composition.md)
- [Stateful Session Governance](../stateful-session-governance.md)
- [Audit And Observability](../capabilities/audit-observability.md)
