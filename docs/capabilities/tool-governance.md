# Tool Governance

## What It Does

Tool governance checks agent or MCP-style connector actions before execution.

It can govern:

- connector name
- action name
- user role
- action risk
- side effects
- approval requirements
- rate/budget limits

## Imports

```python
from policyaware import ToolPolicyEngine, ToolRegistry
from policyaware.models import ToolCallRequest
```

## Main APIs

| API | Type | What It Does |
| --- | --- | --- |
| `ToolPolicyEngine.from_file(path)` | class method | Loads MCP/tool governance YAML. |
| `engine.decide(tool_call)` | method | Evaluates connector/action access before the tool is executed. |
| `ToolRegistry(...)` | class | Stores known tools/connectors for governance use. |
| `ToolCallRequest(...)` | model | Standard tool-call request object. |
| `policyaware tools check <file>` | CLI | Tests tool governance policy from the command line. |

## `ToolCallRequest` Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `agent_id` | `str` | Agent or application requesting the tool call. |
| `connector_id` | `str` | Connector name, such as `github`, `jira`, or `salesforce`. |
| `action` | `str` | Action name, such as `read_file`, `create_pr`, or `delete_branch`. |
| `arguments` | `dict` | Tool arguments that may be inspected or audited. |
| `tenant` | `str` | Tenant boundary for the tool call. |
| `user` | `dict` | User identity and role. |
| `context` | `dict` | Extra risk, region, domain, or workflow metadata. |
| `call_id` | `str` | Generated tool-call ID unless supplied. |

## `ToolDecision` Result Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `decision` | `Decision` | Final result: `allow`, `deny`, `conditional_allow`, or `require_approval`. |
| `connector_id` | `str` | Connector that was evaluated. |
| `action` | `str` | Action that was evaluated. |
| `reason` | `str` | Human-readable decision reason. |
| `reason_codes` | `list[str]` | Machine-readable reason codes. |
| `matched_rules` | `list[str]` | Connector/action rules that matched. |
| `limits` | `dict` | Budget or rate-limit metadata when configured. |
| `approval_required` | `bool` | True when the action needs human approval. |

## Tool Policy Example

```yaml
id: mcp_tool_governance
schema_version: "0.2"
default: deny

connectors:
  - id: github
    type: mcp
    risk: medium
    actions:
      read_file:
        effect: allow
        risk: low
        side_effect: none
        when:
          user.role_in: ["developer", "security_engineer"]
      create_pr:
        effect: require_approval
        risk: high
        side_effect: write
        when:
          user.role_in: ["developer", "maintainer"]
      delete_branch:
        effect: deny
        risk: critical
        side_effect: delete
```

## Python Example

```python
from policyaware import ToolPolicyEngine
from policyaware.models import ToolCallRequest

engine = ToolPolicyEngine.from_file("examples/policies/tool-governance.yaml")

decision = engine.decide(
    ToolCallRequest(
        agent_id="code_assistant",
        connector_id="github",
        action="create_pr",
        user={"id": "dev1", "role": "developer"},
    )
)

print(decision.decision.value)
print(decision.reason_codes)
print(decision.approval_required)
```

## CLI

```bash
policyaware tools check examples/policies/tool-governance.yaml \
  --agent code_assistant \
  --connector github \
  --action create_pr \
  --role developer
```
