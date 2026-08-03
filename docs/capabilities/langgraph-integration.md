# LangGraph Integration

PolicyAware supports LangGraph-style agent governance through `PolicyAwareNodeGuard`.

The integration is dependency-free because LangGraph nodes are ordinary Python callables. You can use the guard inside a node or wrap a node before adding it to a graph.

## Install

```bash
pip install policyaware
```

## Basic Node Guard

```python
from policyaware import PolicyAwareNodeGuard

guard = PolicyAwareNodeGuard(config="policyaware.yaml")

def support_node(state):
    return {"messages": [{"role": "assistant", "content": "node result"}]}

guarded_support_node = guard.guard_node(support_node)
```

If PolicyAware denies the state, the wrapped node does not run. Instead, it returns a state update with:

- `policyaware.allowed`
- `policyaware.decision`
- `policyaware.trace_id`
- `policyaware.reason_codes`
- `policyaware.matched_rules`
- `messages`

## Check State Manually

```python
result = guard.check_state(
    {
        "tenant": "acme",
        "user": {"id": "u_123", "role": "support_agent"},
        "context": {"region": "us", "risk": "medium", "task_type": "agent"},
        "messages": [{"role": "user", "content": "Summarize this case."}],
    }
)

if not result.allowed:
    return result.state_update
```

## Tool Governance

```python
guard = PolicyAwareNodeGuard(
    config="policyaware.yaml",
    tool_policy="tool-governance.yaml",
)

decision = guard.check_tool_call(
    agent_id="support_agent_1",
    connector_id="crm",
    action="update_customer",
    arguments={"customer_id": "cust_123"},
    user={"role": "support_agent"},
)

print(decision.decision.value)
print(decision.approval_required)
```

## Tool Policy YAML

```yaml
default: deny

connectors:
  - id: crm
    actions:
      read_customer:
        effect: allow
        when:
          user.role_in: ["support_agent", "manager"]

      update_customer:
        effect: require_approval
        when:
          user.role_in: ["support_agent", "manager"]

      delete_customer:
        effect: deny
```

## APIs

| API | Purpose |
| --- | --- |
| `PolicyAwareNodeGuard(config=...)` | Create a graph-node guard from a YAML policy. |
| `guard.check_state(state)` | Evaluate graph state before node execution. |
| `guard.guard_node(node)` | Wrap a sync or async node with a policy check. |
| `guard.aguard_node(node, state)` | Await an async node after a policy check. |
| `guard.check_tool_call(...)` | Evaluate an MCP-style tool call before execution. |
| `PolicyAwareNodeResult` | Captures `allowed`, `decision`, `response`, and `state_update`. |

## Runnable Example

See:

```text
examples/langgraph-agent-governance/
```
