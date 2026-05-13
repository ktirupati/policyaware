# PolicyAware Capabilities

PolicyAware is a policy-aware control plane for governed AI execution. The capabilities below are documented independently so users can adopt one feature at a time.

Each capability guide includes copy/paste code, YAML examples, and API tables that show the important classes, methods, result fields, and policy fields.

## Capability Map

| Category | Capability | Primary APIs |
| --- | --- | --- |
| Data protection | Detect and redact PII, PHI, secrets, and sensitive strings | `DataProtectionEngine`, `PresidioPIIClassifier` |
| Policy enforcement | Decide allow, deny, conditional allow, or approval required | `PolicyEngine`, `PolicySchemaValidator` |
| Gateway orchestration | Run request through data checks, risk, policy, routing, eval, audit | `Gateway`, `GatewayRequest` |
| Risk classification | Score requests as low, medium, high, or critical | `RiskClassifier` |
| Model routing | Select compliant model/provider by region, cost, risk, capability | `ModelRouter`, `ProviderRegistry` |
| Provider adapters | Call local or external model backends | `SimulatedProvider`, provider adapters |
| Tool governance | Govern MCP/agent connector and action permissions | `ToolPolicyEngine`, `ToolRegistry` |
| Evaluation | Check leakage, citations, policy consistency, golden datasets | `RuntimeEvaluator`, `EvalSuiteRunner` |
| Audit | Persist traces, replay requests, generate evidence bundles | `AuditLogger`, `SQLiteAuditLogger`, `AuditBundleWriter`, `TraceViewer` |
| Observability | Export local traces as Prometheus or OpenTelemetry-shaped data | `PrometheusExporter`, `OpenTelemetryJsonExporter` |
| ML-assisted signals | Add optional PII, prompt-injection, domain/risk classifier signals | `CompositeMLClassifier`, `MLSignal`, ML adapters |

## Capability Guides

- [Data Protection](capabilities/data-protection.md)
- [Ready-To-Use YAML Policies](capabilities/ready-to-use-yaml.md)
- [YAML Policy Templates](yaml-policy-templates.md)
- [Policy Enforcement](capabilities/policy-enforcement.md)
- [Gateway Orchestration](capabilities/gateway-orchestration.md)
- [Risk Classification](capabilities/risk-classification.md)
- [Model Routing And Providers](capabilities/model-routing-providers.md)
- [Provider Adapter Examples](provider-adapter-examples.md)
- [Tool Governance](capabilities/tool-governance.md)
- [Evaluation](capabilities/evaluation.md)
- [Audit And Observability](capabilities/audit-observability.md)
- [ML-Assisted Signals](capabilities/ml-assisted-signals.md)

## API Discovery Tables

| Guide | API Tables Included |
| --- | --- |
| [Data Protection](capabilities/data-protection.md) | Main APIs, `DataFindings` result fields, policy fields |
| [Policy Enforcement](capabilities/policy-enforcement.md) | Main APIs, `PolicyDecision` result fields, YAML policy context fields |
| [Gateway Orchestration](capabilities/gateway-orchestration.md) | Main APIs, `GatewayRequest` fields, `GatewayResponse` fields |
| [Risk Classification](capabilities/risk-classification.md) | Main APIs, `RiskAssessment` result fields, common risk inputs |
| [Model Routing And Providers](capabilities/model-routing-providers.md) | Main APIs, `ModelCandidate` fields, `RouteDecision` result fields, provider names |
| [Tool Governance](capabilities/tool-governance.md) | Main APIs, `ToolCallRequest` fields, `ToolDecision` result fields |
| [Evaluation](capabilities/evaluation.md) | Main APIs, `EvalResult` fields, `EvalReport` fields, eval case YAML fields |
| [Audit And Observability](capabilities/audit-observability.md) | Main APIs, `AuditTrace` fields, exporter APIs |
| [ML-Assisted Signals](capabilities/ml-assisted-signals.md) | Main APIs, `MLSignal` fields, YAML policy fields |

## Recommended Learning Path

1. Start with `DataProtectionEngine` for simple string checks.
2. Add a YAML policy and test `PolicyEngine`.
3. Use `Gateway` for complete request handling.
4. Add `RiskClassifier`, `ModelRouter`, and audit storage.
5. Add tool governance for agents.
6. Add optional ML signals only after the rules-based path is understood.
