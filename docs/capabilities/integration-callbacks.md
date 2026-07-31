# LangChain And LlamaIndex Callback Integrations

PolicyAware includes lightweight callback handlers for LangChain-style and LlamaIndex-style LLM pipelines. They do not require LangChain or LlamaIndex as base dependencies.

Use these callbacks when you already have an LLM pipeline and want PolicyAware to observe prompts, aggregate streamed tokens, check policy, detect sensitive output leakage, score runtime evals, and expose a governance result object.

## Install

```bash
pip install policyaware
```

No extra install is required for the callback classes themselves.

## What The Callbacks Do

| Capability | Behavior |
| --- | --- |
| Prompt capture | Reads prompt/messages/query payloads from framework callback events. |
| Stream aggregation | Collects streamed tokens with `on_llm_new_token` without blocking token delivery. |
| Policy decision | Applies the configured YAML policy to the prompt and request context. |
| Risk classification | Produces low, medium, high, or critical risk assessment. |
| Data protection | Detects PII, PHI, secrets, and sensitive output leakage. |
| Runtime evals | Runs leakage, citation, and policy-consistency checks after output completion. |
| Token accounting | Estimates input and output tokens for cost and audit workflows. |
| Result object | Stores `last_result` as a machine-readable `PolicyAwareCallbackResult`. |

The callbacks do not call a model provider themselves. Your LangChain or LlamaIndex pipeline still owns model execution. PolicyAware observes the prompt and final generated output so the result can be audited, reported, and used by application logic.

## LangChain One-Line Usage

```python
from policyaware.integrations.langchain import PolicyAwareCallbackHandler

policyaware_callback = PolicyAwareCallbackHandler(config="policyaware.yaml")

# Example shape for LangChain-style calls:
response = chain.invoke(
    {"question": "Can you summarize this customer ticket?"},
    config={"callbacks": [policyaware_callback]},
)

result = policyaware_callback.last_result
print(result.policy_decision.decision)
print(result.risk.tier)
print(result.output_findings.contains_sensitive)
```

## LangChain Streaming Example

```python
from policyaware.integrations.langchain import PolicyAwareCallbackHandler

handler = PolicyAwareCallbackHandler(
    config="policyaware.yaml",
    tenant="acme",
    user={"id": "u_123", "role": "support_agent"},
    context={"region": "us", "risk": "low", "task_type": "support_chat"},
)

handler.on_llm_start(prompts=["Email jane@example.com with the ticket summary."])

for token in ["Safe ", "summary ", "without ", "private ", "data."]:
    handler.on_llm_new_token(token)

result = handler.on_llm_end()

print(result.to_dict())
```

Expected behavior:

- input PII is detected
- policy may return `conditional_allow`
- streamed output is aggregated into `result.output_text`
- output leakage checks run after completion
- token counts are available as `result.input_tokens` and `result.output_tokens`

## LlamaIndex Usage

```python
from policyaware.integrations.llamaindex import PolicyAwareCallbackHandler

handler = PolicyAwareCallbackHandler(
    config="policyaware.yaml",
    tenant="acme",
    user={"id": "u_456", "role": "analyst"},
)

handler.on_event_start(payload={"query_str": "Answer with citations from the policy documents."})
handler.on_llm_new_token("The approved policy requires citation review [doc-1].")
result = handler.on_event_end(payload={})

print(result.policy_decision.decision)
print(result.evals)
```

The LlamaIndex callback defaults to RAG-oriented context:

```python
{"region": "us", "task_type": "rag_answer", "risk": "low", "require_citations": True}
```

Override it when needed:

```python
handler = PolicyAwareCallbackHandler(
    config="policyaware.yaml",
    context={"region": "us", "task_type": "analytics", "risk": "medium"},
)
```

## Result Fields

| Field | Meaning |
| --- | --- |
| `prompt_text` | Captured prompt/query/messages as text. |
| `output_text` | Aggregated final model output. |
| `policy_decision` | `PolicyDecision` with allow/deny/conditional/approval outcome. |
| `risk` | `RiskAssessment` with tier, score, factors, and reason codes. |
| `input_findings` | Sensitive-data findings for the prompt. |
| `output_findings` | Sensitive-data findings for the generated answer. |
| `evals` | Runtime eval checks such as leakage and citations. |
| `input_tokens` | Estimated prompt token count. |
| `output_tokens` | Estimated output token count. |
| `allowed` | Convenience boolean for allow or conditional allow. |
| `contains_output_sensitive_data` | Convenience boolean for output leakage. |
| `to_dict()` | JSON-ready result dictionary for logging or dashboards. |

## Copy-Paste Policy

```yaml
id: callback_guardrails_policy
default: deny

rules:
  - name: block_secrets
    effect: deny
    when:
      data.contains_secrets: true

  - name: allow_enterprise_users
    effect: allow
    when:
      user.role_in: ["developer", "support_agent", "analyst"]
      request.region: "us"
      request.risk_in: ["low", "medium"]

  - name: redact_pii
    effect: transform
    action: redact
    when:
      data.contains_pii: true
      user.role_not_in: ["privacy_admin", "compliance_officer"]

  - name: require_approval_for_high_risk
    effect: require_approval
    when:
      risk.tier_in: ["high", "critical"]
```

## Recommended Use

Use callbacks for application observability, audit, and post-generation compliance checks in existing LangChain/LlamaIndex applications.

Use `Gateway.chat(...)` when PolicyAware should directly control request flow, provider routing, output guardrails, and audit trace recording end to end.
