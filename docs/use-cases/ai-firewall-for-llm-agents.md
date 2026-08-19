# AI Firewall For LLM Agents

PolicyAware can be used as a deterministic AI firewall for LLM agents. It checks prompts, request context, tool calls, risk tiers, token budgets, model routing, and audit traces before an agent is allowed to act.

This is useful when you are searching for how to stop autonomous agent runaway loops, how to enforce deny-by-default LLM gateway behavior, or how to add a local Python AI firewall with `pip install policyaware`.

## Why This Exists

Traditional guardrails usually focus on model text. PolicyAware focuses on governed execution:

- Who is the user?
- What tenant, region, role, and task is involved?
- Is sensitive data present?
- Is the agent trying to call a tool?
- Is the action destructive or expensive?
- Should the request be allowed, redacted, routed, denied, or sent for approval?

## Install

```bash
pip install policyaware
```

## Copy-Paste Policy

```yaml
name: ai-firewall-agent-policy
version: 1
default_decision: deny

data_protection:
  redact_pii: true
  redact_phi: true
  redact_secrets: true

budgets:
  default:
    max_input_tokens: 4000
    max_output_tokens: 1200
    max_tool_calls: 5
  high_risk:
    max_input_tokens: 2000
    max_output_tokens: 600
    max_tool_calls: 1

rules:
  - id: allow-low-risk-support
    description: Allow low-risk support requests after redaction.
    effect: allow
    when:
      role_in: ["support_agent", "admin"]
      risk_in: ["low", "medium"]
      task_type_in: ["summarization", "support_response"]

  - id: require-approval-for-high-risk-agentic-actions
    description: Human approval is required for high-risk autonomous actions.
    effect: require_approval
    when:
      autonomy_level_in: ["agentic", "autonomous"]
      risk_in: ["high", "critical"]

  - id: deny-critical-unapproved
    description: Critical requests fail closed unless handled by a stricter approval path.
    effect: deny
    when:
      risk_in: ["critical"]
```

## Python Example

```python
from policyaware import Gateway, GatewayRequest

gateway = Gateway.from_policy_file("policyaware.yaml")

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="agent-platform",
        user={"id": "u_123", "role": "support_agent"},
        context={
            "region": "us",
            "task_type": "support_response",
            "risk": "medium",
            "autonomy_level": "agentic",
        },
        messages=[
            {
                "role": "user",
                "content": "Draft a reply to customer jane@example.com about case ACME-42.",
            }
        ],
    )
)

print(response.policy.decision)
print(response.policy.reason_codes)
print(response.trace_id)
```

## CLI Checks

```bash
policyaware policy validate policyaware.yaml
policyaware risk classify "Email jane@example.com about customer case ACME-42" --domain support --autonomy agentic
policyaware dev simulate
```

## What PolicyAware Adds

| Need | PolicyAware Capability |
| --- | --- |
| Deny-by-default LLM gateway | `default_decision: deny` |
| Stop runaway autonomous agents | Token, tool-call, risk, and approval limits |
| Explain why an action was blocked | Reason codes and structured rejections |
| Route sensitive requests safely | Risk-aware model routing |
| Give auditors evidence | Audit traces and policy decision logs |

## FAQ

### Is PolicyAware AI-based or rules-based?

The core enforcement path is deterministic and rules-based. Optional ML integrations can add signals for PII, prompt injection, or domain/risk classification, but policy decisions remain explainable.

### Does this replace NeMo Guardrails or Guardrails AI?

No. PolicyAware can orchestrate those tools. Use PolicyAware as the governance and policy control layer, then add conversational guardrails where deeper model-output behavior checks are needed.

### Does this work only in Python?

The SDK is Python, and the HTTP sidecar lets Node.js, Go, Java, Rust, and other services call PolicyAware over HTTP.
