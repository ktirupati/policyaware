# Capabilities, Boundaries, And Deployment Choices

PolicyAware is an application-level AI governance framework. This page summarizes what its current integration points provide and where teams should pair it with other systems. It is intended to make adoption decisions concrete, not to imply that every optional or roadmap-oriented capability is included in the base package.

## Current Scope At A Glance

| Area | PolicyAware provides | It does not provide |
| --- | --- | --- |
| Runtime governance | Deterministic policy decisions for requests, context, routing, budgets, and tool actions; optional data-protection and guardrail integrations. | A universal semantic judge that understands every implied policy violation without configuration or optional models. |
| Validator ecosystem | Built-in policy/rule checks and adapter points for configured external or custom validators. | A first-party, centrally curated catalog comparable to a large community validator hub. Availability, quality, dependencies, and licenses of external validators vary. |
| Stateful sessions | Threshold-based tracking of cumulative sensitive findings and repeated tool actions when the application supplies stable session identity and uses a supported state store. | Automatic semantic detection that a conversation has gradually gone off-topic, or a general-purpose dialogue-flow engine. |
| Audit and compliance evidence | Decisions from configured policy engines can include policy ID/version/schema version and a SHA-256 configuration fingerprint; audit bundles, scan findings, and telemetry can support downstream review. Audit snapshots can omit free-text payloads in metadata mode. | Automatic, legally validated mapping of every event to NIST AI RMF, ISO/IEC 42001, or EU AI Act controls; a formal compliance assessment, certification, or GRC platform. |
| Deployment | Python SDK/CLI and an HTTP sidecar API for explicitly submitted governance checks. The sidecar can separate the policy process from the application process. | A mature, transparent, OpenAI-compatible reverse proxy or a turnkey high-throughput, multi-tenant, multi-region gateway with fleet-wide push updates and built-in connection-pool management. |
| Execution security | Policy checks before governed tool actions, plus structured deny and approval-required results. | OS-level sandboxing, secure-memory isolation, guaranteed RAM wiping, or protection after an attacker compromises the application process. |

## Choose The Right Layer

- Use the **SDK** when you want direct Python integration and can make every relevant model/tool path call PolicyAware.
- Use the **sidecar** when you need a separate process or need non-Python services to submit explicit checks. The caller must honor the response; the sidecar does not transparently intercept arbitrary network traffic.
- Use a **dedicated AI gateway** when you need provider-compatible proxying, centralized key management, connection pooling, high-throughput scaling, or multi-region traffic management. PolicyAware can complement that gateway with application-specific policy and tool governance.
- Use **NeMo Guardrails** or another dialogue orchestration system when you need explicit multi-turn conversational flows, branching, or topic steering; PolicyAware can continue to enforce the surrounding policy and tool permissions.
- Use a **validator framework/catalog** when you need a broad library of specialized schema, semantic, or domain validators. Integrate selected validators into PolicyAware where its decision and audit model is useful.
- Use an **enterprise GRC platform** when you need AI inventory, obligation management, control ownership, framework crosswalks, and executive reporting. PolicyAware's technical evidence can be an input, but requires review and mapping.

## Stateful Conversation Checks

Session governance is useful for measurable cumulative signals, for example:

```python
from policyaware import Gateway, GatewayRequest, SessionStateMonitor

gateway = Gateway.from_policy_file("policyaware.yaml")
gateway.session_monitor = SessionStateMonitor(
    max_sensitive_findings_per_session=10,
    max_tool_calls_per_session=25,
    max_same_tool_action_per_session=10,
)

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="support-assistant",
        user={"id": "user-123", "role": "support_agent"},
        context={"session_id": "conversation-456"},
        messages=[{"role": "user", "content": "Summarize this support request."}],
    )
)
print(response.policy.decision, response.metadata.get("session"))
```

The stable `session_id` lets the configured monitor associate checks with a session. These counters do not infer semantic drift or replace a dialogue-state model. The default monitor is process-local; see [Stateful Session Governance](stateful-session-governance.md) for persistence and scaling guidance.

## Audit Evidence Versus Compliance Mapping

PolicyAware records technical events such as policy decisions, matched rules, reason codes, and trace identifiers. An organization still needs to decide which controls those events support, retain source and approval evidence, review gaps, and determine whether its overall obligations are met. Do not treat a policy pack, scan report, or audit bundle as proof of compliance.

Audit traces preserve policy provenance when the recorded decision came from an engine that supplies it. The fingerprint and optional human-managed revision help identify loaded content, but are not a cryptographic signature, approval record, or compliance mapping. Full request/response snapshots remain the default for compatibility; metadata mode omits payload bodies but still records trace-level identifiers. Use opaque IDs and configure retention/access controls.

## Performance And Scale

The sidecar and SDK are not equivalent to a production-validated high-throughput proxy. Benchmark the complete path (including serialization, network hops, optional validators, storage, and provider calls) under expected concurrency before deployment. Read [Benchmarks](benchmarks.md), [HTTP Sidecar Gateway](sidecar-http-gateway.md), and [Limitations And Scope](limitations.md).

## Further Reading

- [Limitations And Scope](limitations.md)
- [Comparison](comparison.md)
- [Security Boundaries](security-boundaries.md)
- [Stateful Session Governance](stateful-session-governance.md)
- [Guardrail Integrations](capabilities/guardrails-integrations.md)
- [Audit And Observability](capabilities/audit-observability.md)
- [HTTP Sidecar Gateway](sidecar-http-gateway.md)
