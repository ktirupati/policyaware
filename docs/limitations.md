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
| Real provider calls | Provider adapters are implemented structurally, but live calls require user-supplied credentials, endpoints, model names, regions, quotas, and cloud permissions. |
| Callback enforcement | LangChain/LlamaIndex callbacks observe prompts and outputs, aggregate streamed tokens, and report governance results. They do not replace full execution control from `Gateway.chat(...)`. |
| Static scanning | `policyaware scan` finds likely risks through static analysis. It does not prove runtime exploitability or replace secure code review. |
| ML classifiers | ML integrations are optional and license/dependency dependent. Users should validate model behavior, thresholds, and licenses for their environment. |
| Guardrail libraries | NeMo Guardrails and Guardrails AI are optional adapters. Their behavior depends on user-provided guardrail configurations. |
| PHI detection | Built-in PHI detection is pattern/rule oriented. Healthcare production use should add domain-specific policies and optional stronger detectors. |
| Prompt injection | PolicyAware can detect known risky patterns and support optional ML prompt-injection signals, but prompt-injection defense should be layered with tool permissions and human review for high-risk actions. |
| Compliance | PolicyAware produces governance evidence, but it is not a legal certification tool by itself. Compliance teams must review policies, audit retention, controls, and deployment procedures. |

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

## Design Principle

PolicyAware should make governed AI execution easier to adopt without hiding important operational responsibility. The framework provides reusable controls and evidence, while each enterprise remains responsible for policy content, model credentials, data retention, regulatory interpretation, and deployment validation.
