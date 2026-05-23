# Why PolicyAware Exists

PolicyAware sits between application code, models, retrieval systems, and tools. It is not only a guardrail library, not only an AI gateway, and not only a model router.

It exists for teams that need governed AI execution across LLM apps, RAG systems, and agents.

## Short Positioning

Add deny-by-default policy, PII redaction, tool governance, model routing, evaluation, and audit traces to LLM apps in minutes.

## Category Fit

| Category | What It Usually Does | Where It Helps | Where It Is Not Enough |
| --- | --- | --- | --- |
| Guardrails | Validate prompts or outputs against safety, format, or quality rules. | Helpful for prompt safety, structured outputs, toxicity checks, and response validation. | Usually does not provide full request context policy, model routing, tool permissions, approval workflows, or audit evidence. |
| AI gateway | Proxy requests to one or more model providers. | Helpful for provider abstraction, API keys, usage tracking, rate limits, and fallback routing. | Often model-call focused, not policy-first across prompts, context, tools, RAG quality, approvals, and compliance traces. |
| Model router | Select the best model for a request. | Helpful for cost, latency, availability, provider failover, and quality tradeoffs. | Usually does not decide whether a request is legally, organizationally, or operationally allowed before routing. |
| PolicyAware | Enforce policy before model/tool execution, then evaluate and audit the result. | Helpful for enterprise governance across LLMs, RAG, AI agents, MCP tools, model routing, approvals, and compliance review. | It is a control plane starter, not a hosted SaaS dashboard or replacement for legal/security review. |

## PolicyAware Compared

| Question | Guardrails | AI Gateway | Model Router | PolicyAware |
| --- | --- | --- | --- | --- |
| Can it block unsafe prompts before model execution? | Sometimes | Sometimes | No | Yes |
| Can it redact PII/PHI/secrets before execution? | Sometimes | Sometimes | No | Yes |
| Can it use user role, tenant, region, domain, and risk level in decisions? | Limited | Limited | Limited | Yes |
| Is deny-by-default the default posture? | Usually no | Usually no | No | Yes |
| Can it govern MCP or agent tool calls? | Usually no | Sometimes | No | Yes |
| Can it require approval for risky actions? | Usually no | Sometimes | No | Yes |
| Can it route across providers after policy approval? | No | Yes | Yes | Yes |
| Can it evaluate RAG citation/grounding and leakage? | Sometimes | Limited | No | Yes |
| Can it emit audit traces with reason codes? | Limited | Sometimes | Limited | Yes |
| Can it generate compliance evidence artifacts? | Usually no | Usually no | No | Yes |

## When To Use PolicyAware

Use PolicyAware when you need one or more of these:

- You want model and tool calls to be denied unless policy explicitly allows them.
- You need PII, PHI, or secret detection and redaction before prompts reach an LLM.
- You need policy decisions based on user role, tenant, region, domain, risk, and task type.
- You are building AI agents that call tools through MCP-style connectors.
- You need approval workflows for write, delete, payment, deploy, or high-impact actions.
- You need routing across local and external models, but only after policy approval.
- You need audit traces, reason codes, and replayable evidence for security or compliance review.
- You need evaluations tied to governance outcomes, not only model quality.

## When A Simpler Tool Is Enough

Use a guardrails-only library when:

- You only need output formatting or response validation.
- You do not need RBAC, tenant, region, approval, routing, or audit traces.

Use an AI gateway-only product when:

- Your main need is provider abstraction, centralized keys, rate limits, and usage tracking.
- You already have another system enforcing enterprise policy and tool governance.

Use a model router-only library when:

- You only need cost, quality, latency, or provider failover decisions.
- You do not need to decide whether the request should be allowed in the first place.

## Practical Example

A customer-support copilot receives this prompt:

```text
Email jane@example.com and refund the customer $500.
```

A guardrails library may check the prompt or output for safety.

An AI gateway may forward the request to the selected provider.

A model router may choose the cheapest or fastest model.

PolicyAware can:

1. Detect PII in the prompt.
2. Classify the request as higher risk because it includes a payment-like action.
3. Apply role, tenant, region, and task policy.
4. Redact the email address if the role is allowed to continue.
5. Require approval before the refund action.
6. Route only approved model calls to compliant providers.
7. Evaluate the final response for leakage or missing citations.
8. Write a trace with decision, reason codes, matched rules, risk tier, route, evals, and cost.

## One-Line Category

PolicyAware is a policy-aware control plane for governed AI execution.

It combines the useful parts of guardrails, gateways, and routing, but organizes them around enterprise policy, tool governance, explainable decisions, evaluations, and auditability.

