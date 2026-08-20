# Limitations And Scope

PolicyAware is designed to be practical, modular, and enterprise-friendly. This page explains what the framework currently does well and what users must still configure or validate in their own environment.

## What PolicyAware Does Well

- Enforces deny-by-default YAML policy decisions.
- Detects and redacts PII, PHI, secrets, and sensitive data patterns.
- Classifies request risk using deterministic rules and optional ML signals.
- Governs MCP-style tool connectors and actions before execution.
- Routes model requests through a vendor-neutral provider abstraction.
- Evaluates outputs for leakage, citations, and policy consistency.
- Writes audit traces and compliance evidence artifacts.
- Scans local repositories for AI governance, compliance, and data-leakage risks.
- Provides Python SDK, CLI, middleware shims, and LangChain/LlamaIndex callbacks.

## Important Current Limitations

| Area | Current Scope |
| --- | --- |
| Best-fit scope | PolicyAware is purpose-built for LLM apps, RAG pipelines, MCP/tool workflows, autonomous agents, and AI governance scans. For ordinary web APIs or microservices that do not call models or tools, a standard API gateway, WAF, auth middleware, or secrets scanner is usually the better first layer. |
| Deployment model | PolicyAware is an adoption-ready open-source framework that teams embed and operate in their own AI applications, platforms, and CI workflows. It is not a hosted SaaS product; teams bring their preferred identity, storage, dashboard, and workflow systems. |
| Real provider calls | Provider adapters are implemented structurally, but live calls require user-supplied credentials, endpoints, model names, regions, quotas, and cloud permissions. |
| Callback enforcement | LangChain/LlamaIndex callbacks observe prompts and outputs, aggregate streamed tokens, and report governance results. They do not replace full execution control from `Gateway.chat(...)`. |
| Static scanning | `policyaware scan` finds likely risks through static analysis. It does not prove runtime exploitability or replace secure code review. |
| Execution-plane memory | PolicyAware governs requests, policies, tools, routing, evaluation, and audit decisions. It does not provide secure-memory isolation, encrypted in-memory Python objects, `mlock`, or guaranteed memory wiping for secrets already inside the application process. |
| Tool execution sandboxing | PolicyAware can deny or require approval before tool execution, but it does not natively run approved tools inside Docker, Wasm, gVisor, Firecracker, or a Kubernetes job sandbox. Teams must provide execution isolation for high-risk or untrusted tools. |
| ML classifiers | The base package uses local rules and patterns. Deeper ML detection, such as Presidio privacy detection or ProtectAI/Transformers classifiers, is optional and license/dependency dependent. Users should validate model behavior, thresholds, and licenses for their environment. |
| Guardrail libraries | NeMo Guardrails and Guardrails AI are optional adapters. Their behavior depends on user-provided guardrail configurations. |
| PHI detection | Built-in PHI detection is pattern/rule oriented. Healthcare production use should add domain-specific policies and optional stronger detectors. |
| Prompt injection | PolicyAware can detect known risky patterns and support optional ML prompt-injection signals, but prompt-injection defense should be layered with tool permissions and human review for high-risk actions. |
| Semantic governance | The core package is deterministic and explicit by design. It uses YAML policy, structured metadata, risk tiers, and pattern-based checks. Subtle social engineering, implied policy violations, or adversarial prompt injection may require optional semantic classifiers, guardrail adapters, golden datasets, and human review. |
| HITL orchestration | PolicyAware can return approval-required decisions, but a full enterprise approval workflow also needs a durable queue, approval identity, secure resume/terminate APIs, timeouts, escalation, and workflow-system integrations such as Slack, PagerDuty, ServiceNow, Jira, or an internal approval API. |
| Latency overhead | PolicyAware adds governance work before and after model calls. The base rules path is local and lightweight, cached policy loading avoids YAML parsing on every request, and teams can benchmark overhead with their own routes. Optional ML classifiers, external guardrail engines, and very large policy stacks can add more overhead. |
| Compliance | PolicyAware produces governance evidence, but it is not a legal certification tool by itself. Compliance teams must review policies, audit retention, controls, and deployment procedures. |

## Best Fit And Trade-Offs

PolicyAware is strongest when an application uses LLMs, RAG, MCP-style tools, autonomous agents, or AI workflows that need policy, risk, audit, data protection, and routing decisions in one place.

It is usually not necessary for ordinary CRUD services, internal APIs, or microservices that do not send prompts to models or allow agents to invoke tools. In those cases, start with standard application security controls and add PolicyAware only where AI execution needs governance.

Execution-plane security must be layered. For high-assurance systems, combine PolicyAware decisions with process isolation, container hardening, dependency scanning, short-lived credentials, secret managers, least-privilege service accounts, and separate read/write tool identities. Do not rely on a Python SDK to guarantee RAM-level containment or OS-level privilege reduction.

The base install is intentionally lightweight. It provides deterministic rules, YAML policy validation, data-protection patterns, tool governance, scan reports, audit traces, routing abstractions, and CLI workflows without forcing heavy ML dependencies. When teams need deeper PII detection, prompt-injection signals, conversational guardrails, or framework-specific behavior, they can opt into Presidio, ProtectAI/Transformers, NeMo Guardrails, Guardrails AI, Haystack, or provider-specific extras.

Optional extras can materially increase container size. `policyaware[privacy]` adds Presidio and spaCy, `policyaware[ml]` adds Transformers and Torch, and `policyaware[guardrails]` adds external guardrail framework dependencies. For production images, install only the extras required by the specific service instead of defaulting to `policyaware[all]`.

Semantic safety should also be layered. Keep deterministic policy decisions as the auditable enforcement base, then add optional semantic signals where the risk profile requires deeper prompt-injection, social-engineering, domain-risk, or hallucination checks. This preserves explainability while allowing stronger detection for regulated or high-risk workflows.

Approval decisions should be treated as governance outputs unless a workflow store is connected. A `require_approval` decision tells the application that human review is needed; production systems should pair that decision with durable state, approver identity, timeout behavior, escalation rules, and audit logging before resuming an agent or tool action.

Latency should be treated like any other production engineering concern: measure it in the real request path. Use cached policies, composed policy bundles, the sidecar mode, selective optional ML usage, and CI scan checks to keep runtime enforcement focused on decisions that must happen at request time.

## Deployment Scope

PolicyAware should be evaluated as a production-oriented governance control plane that can be embedded into enterprise AI systems.

It provides native policy enforcement, local scanning, data protection patterns, tool governance, audit traces, routing abstractions, eval hooks, docs, and CLI workflows. Enterprise teams can connect their preferred SSO, approval workflow, SIEM, GRC, dashboard, or long-term storage systems around these controls.

It also intentionally orchestrates specialized tools instead of replacing all of them. For example, Microsoft Presidio can provide stronger PII detection, ProtectAI/Transformers can provide prompt-injection or domain-risk signals, and NeMo Guardrails or Guardrails AI can provide deeper guardrail behavior. Without these optional extras, native coverage is lighter but faster and easier to install.

This design is intentional: `pip install policyaware` stays lightweight, while production teams can add heavier integrations only when their risk profile requires them.

## Recommended Production Validation

Before using PolicyAware in production:

1. Validate policy YAML against real roles, tenants, regions, and business workflows.
2. Test provider adapters with your actual credentials, endpoints, quotas, and model names.
3. Run golden dataset evaluations for expected allow, deny, redact, and approval paths.
4. Tune scan exclusions, severity thresholds, and baseline files for your repository.
5. Configure audit storage and retention according to enterprise requirements.
6. Review optional ML and guardrail dependency licenses.
7. Add approval integrations for high-risk or regulated workflows.
8. Confirm that callbacks are used for observation and `Gateway.chat(...)` is used where central execution control is required.
9. Benchmark request-time overhead in your own application path, especially if optional ML or external guardrail engines are enabled.

## Design Principle

PolicyAware should make governed AI execution easier to adopt without hiding important operational responsibility. The framework provides reusable controls and evidence, while each enterprise remains responsible for policy content, model credentials, data retention, regulatory interpretation, and deployment validation.
