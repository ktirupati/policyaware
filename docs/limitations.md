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
| Deployment model | PolicyAware is an adoption-ready open-source framework that teams embed and operate in their own AI applications, platforms, and CI workflows. It is not a hosted SaaS product; teams bring their preferred identity, storage, dashboard, and workflow systems. |
| Real provider calls | Provider adapters are implemented structurally, but live calls require user-supplied credentials, endpoints, model names, regions, quotas, and cloud permissions. |
| Callback enforcement | LangChain/LlamaIndex callbacks observe prompts and outputs, aggregate streamed tokens, and report governance results. They do not replace full execution control from `Gateway.chat(...)`. |
| Static scanning | `policyaware scan` finds likely risks through static analysis. It does not prove runtime exploitability or replace secure code review. |
| ML classifiers | The base package uses local rules and patterns. Deeper ML detection, such as Presidio privacy detection or ProtectAI/Transformers classifiers, is optional and license/dependency dependent. Users should validate model behavior, thresholds, and licenses for their environment. |
| Guardrail libraries | NeMo Guardrails and Guardrails AI are optional adapters. Their behavior depends on user-provided guardrail configurations. |
| PHI detection | Built-in PHI detection is pattern/rule oriented. Healthcare production use should add domain-specific policies and optional stronger detectors. |
| Prompt injection | PolicyAware can detect known risky patterns and support optional ML prompt-injection signals, but prompt-injection defense should be layered with tool permissions and human review for high-risk actions. |
| Latency overhead | PolicyAware adds governance work before and after model calls. The base path is local and lightweight, but every layer has some cost; optional ML and external guardrail engines can add more overhead. |
| Compliance | PolicyAware produces governance evidence, but it is not a legal certification tool by itself. Compliance teams must review policies, audit retention, controls, and deployment procedures. |

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
