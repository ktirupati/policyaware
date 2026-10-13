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
| PolicyAware | Enforce policy around model and tool execution, then evaluate and record the result. | Helpful for application-level controls across LLMs, RAG, AI agents, MCP tools, model routing, approvals, and technical evidence for governance review. | It is an embeddable open-source framework, not an organization-wide GRC platform, hosted AI inventory, legal interpretation service, or replacement for compliance review. |

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
| Can it generate technical policy and runtime evidence? | Varies | Varies | Usually not the focus | Yes; evidence still needs organizational review and retention controls. |

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

Short version:

> Use PolicyAware when AI actions need governance, not just generation.

## When A Simpler Tool Is Enough

Use a guardrails-only library when:

- You only need output formatting or response validation.
- Your main goal is to keep a model from producing unsafe text, malformed JSON, or off-policy conversational responses.
- You do not need RBAC, tenant, region, approval, routing, or audit traces.

Use an AI gateway-only product when:

- Your main need is provider abstraction, centralized keys, rate limits, and usage tracking.
- You already have another system enforcing enterprise policy and tool governance.

Use a model router-only library when:

- You only need cost, quality, latency, or provider failover decisions.
- You do not need to decide whether the request should be allowed in the first place.

## Where PolicyAware Stands Today

### Observability And Evaluation Scope

PolicyAware includes governance-focused runtime checks, golden-dataset evaluation, policy decision traces, and telemetry exports. These help enforce and review policy outcomes; they are not a full LLM observability or MLOps analytics suite. PolicyAware does not aim to provide the depth of trace exploration, experiment comparison, production quality analytics, cohort analysis, or drift diagnostics available in dedicated tools. Teams can pair PolicyAware with products such as LangSmith, Arize Phoenix, or Fiddler when they need those workflows. Capabilities vary by product and configuration.

### Deployment And Policy Updates

PolicyAware SDK instances and sidecars check for a shared policy update when a request arrives after the configured refresh TTL expires. For services already integrated with PolicyAware, a policy-only update can take effect without rebuilding each application image. This is not background polling, transparent interception, or push-based fleet control: applications must call the governance API or be explicitly routed through it, and each instance refreshes independently. NeMo Guardrails and Guardrails AI also support service-based deployment options, so avoid describing either as in-process only ([NeMo deployment options](https://docs.nvidia.com/nemo/guardrails/latest/index.html), [Guardrails AI server](https://github.com/guardrails-ai/guardrails-api)).

### GRC And Regulatory Scope

PolicyAware focuses on controls inside AI applications and on technical evidence about those controls. Its policy packs are editable starting points, and its audit bundles, scan reports, and traces can support a governance review or be exported into an organization's existing SIEM/GRC process. These features do not provide a centralized AI inventory, end-to-end regulatory obligation management, legally validated mapping from regulations to application code, or executive GRC reporting. They do not establish that an organization is compliant.

Products such as IBM watsonx.governance, Credo AI, and OneTrust address broader governance workflows, which can include AI inventories, risk assessments, framework-aligned processes, and stakeholder reporting. Exact capabilities vary by product and configuration. PolicyAware can complement those platforms with application-level enforcement and evidence; it should not be presented as a replacement for them.

| Feedback Area | Honest Position |
| --- | --- |
| Deployment model | PolicyAware is an adoption-ready open-source framework that teams embed and operate in their own AI systems. It is not a hosted SaaS product; teams can connect their preferred identity, dashboard, storage, approval, SIEM, or GRC systems. |
| External security engines | PolicyAware has native rules and patterns, but deeper ML detection often comes through optional integrations such as Presidio, ProtectAI/Transformers, NeMo Guardrails, and Guardrails AI. |
| Latency | PolicyAware adds governance steps before and after model/tool execution. The base rules-based path is lightweight; optional ML and external guardrails can add more overhead. |
| Best fit | PolicyAware is strongest when AI systems touch sensitive data, call tools, perform autonomous actions, route across models, or need audit evidence for security/compliance teams. |

## Practical Verdict

Use Guardrails AI or NeMo Guardrails if your main need is conversational safety, structured output validation, or specialized guardrail flows.

Use an AI gateway or LiteLLM-style gateway if your main need is API key management, provider abstraction, retries, rate limits, and model fallback.

Use a model router if your main need is choosing the cheapest, fastest, or highest-quality model.

Use PolicyAware if your AI system has data access, tool access, financial or operational autonomy, regulated-domain exposure, or a security/compliance requirement to explain why a user was allowed, denied, redacted, routed, or sent to approval.

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
