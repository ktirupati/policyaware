# When To Use Gateway, Callback, Tool Governance, Or Scan

PolicyAware has multiple entry points because AI governance happens at multiple layers. This page helps developers choose the right one.

## Quick Decision Table

| Use Case | Recommended Entry Point | Why |
| --- | --- | --- |
| You want PolicyAware to make the model call, route providers, evaluate output, and write traces | `Gateway.chat(...)` | Full request lifecycle control |
| You already have a LangChain app and want governance telemetry | `policyaware.integrations.langchain.PolicyAwareCallbackHandler` | Observes prompt/output without changing the model call |
| You already have a LlamaIndex RAG app and want citation/leakage checks | `policyaware.integrations.llamaindex.PolicyAwareCallbackHandler` | Aggregates streamed output and runs post-generation checks |
| You need to approve or deny MCP-style tool actions | `ToolPolicyEngine.check(...)` | Connector/action governance before execution |
| You want to scan a repository before production | `policyaware scan ./app` | Fast local governance and compliance scan |
| You want to unit test YAML policies | `PolicyEngine.from_file(...).decide(...)` | Pure policy-as-code testing |
| You want only PII/PHI/secrets detection for a string | `DataProtectionEngine.inspect(...)` | Lightweight data protection check |

## Gateway Mode

Use `Gateway.chat(...)` when PolicyAware should sit in the execution path.

```python
from policyaware import Gateway, GatewayRequest

gateway = Gateway.from_policy_file("policyaware.yaml")

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="support-copilot",
        user={"id": "u_123", "role": "support_agent"},
        context={"region": "us", "risk": "low", "task_type": "support"},
        messages=[{"role": "user", "content": "Summarize this ticket."}],
    )
)

print(response.policy.decision)
print(response.route)
print(response.trace_id)
```

Gateway mode is best when you need enforceable model routing, policy decisions, output evaluation, and audit trace creation in one flow.

## Callback Mode

Use callbacks when another framework already owns model execution.

```python
from policyaware.integrations.langchain import PolicyAwareCallbackHandler

callback = PolicyAwareCallbackHandler(config="policyaware.yaml")

response = chain.invoke(
    {"question": "Summarize this customer ticket."},
    config={"callbacks": [callback]},
)

print(callback.last_result.to_dict())
```

Callback mode is best for observability, streamed-token aggregation, output leakage checks, and adoption into existing LangChain/LlamaIndex applications.

## Tool Governance Mode

Use tool governance before an agent calls an MCP-style connector or action.

```python
from policyaware import ToolCallRequest, ToolPolicyEngine

engine = ToolPolicyEngine.from_file("examples/policies/tool-governance.yaml")

decision = engine.check(
    ToolCallRequest(
        agent_id="code_assistant",
        connector_id="github",
        action="create_pr",
        user={"role": "developer"},
        context={"risk": "medium", "region": "us"},
    )
)

print(decision.decision)
print(decision.reason_codes)
```

Tool governance mode is best for connector-level permissions, action-level permissions, approval requirements, and destructive operation controls.

## Scan Mode

Use scan mode before deployment or during CI.

```bash
policyaware scan ./my-ai-app --format html,json,sarif,markdown
policyaware scan ./my-ai-app --config examples/policyaware-scan.yaml --fail-on high
policyaware scan ./my-ai-app --diff --diff-base origin/main
```

Scan mode is best for finding governance gaps in local code, including PII/PHI/secrets, direct LLM calls, missing tool checks, weak routing controls, RAG grounding gaps, and audit gaps.

## Direct Engine Mode

Use direct engines for small scripts, tests, or notebooks.

```python
from policyaware import DataProtectionEngine

engine = DataProtectionEngine()
findings = engine.inspect("Email jane@example.com or call 212-555-7890.")

print(findings.contains_pii)
print(findings.categories)
```

Direct engine mode is best when you want one capability without the full gateway lifecycle.
