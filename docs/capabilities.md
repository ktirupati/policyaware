# PolicyAware Capabilities

PolicyAware is an open-source AI gateway and agent control plane for governed LLM applications, RAG pipelines, MCP-style tools, and autonomous AI agents.

Unlike basic content filters that only check text strings, PolicyAware provides policy-aware governance across requests, tools, models, evaluations, audit traces, and local code scans. The capabilities below are documented independently so users can adopt one feature at a time.

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
| Blocked-action handshakes | Preserve structured denial and approval payloads for API routers, logs, and traces | `PolicyAwareRejection`, `policy_rejection`, `tool_rejection` |
| ML-assisted signals | Add optional PII, prompt-injection, domain/risk classifier signals | `CompositeMLClassifier`, `MLSignal`, ML adapters |
| Local code scan | Scan repositories for AI governance, compliance, PII, PHI, secrets, model calls, tool use, RAG, data residency, and audit gaps | `LocalCodeScanner`, `ScanConfig`, `policyaware scan` |
| Guardrails integrations | Orchestrate NeMo Guardrails, Guardrails AI, or custom validators as optional input/output guards | `NeMoGuardrailsAdapter`, `GuardrailsAIAdapter`, `GuardrailResult` |
| Framework callbacks | Add lightweight LangChain and LlamaIndex callbacks for streamed-token aggregation, policy review, and output leakage checks | `PolicyAwareCallbackHandler`, `PolicyAwareCallbackResult` |
| LangGraph integration | Add dependency-free node/state governance and tool-call checks to graph-based agents | `PolicyAwareNodeGuard`, `PolicyAwareNodeResult` |
| Haystack integration | Add Haystack-style RAG query, output, and agent tool governance components | `PolicyAwareInputComponent`, `PolicyAwareOutputComponent`, `PolicyAwareToolGovernanceComponent` |
| Microsoft AGT-style interop | Export PolicyAware policy, tool, gateway, and audit decisions as dependency-free agent-governance evidence JSON | `to_agt_decision`, `to_agt_tool_evidence`, `to_agt_gateway_evidence`, `to_agt_audit_evidence` |
| Integration recommender | Recommend the best PolicyAware integration from project signals and user needs | `IntegrationRecommender`, `policyaware integrations recommend` |
| CLI usability | Diagnose installs, run examples, create recommendation reports, and migrate policy files | `policyaware doctor`, `policyaware examples`, `policyaware policy migrate` |
| Policy packs | Copy compliance-oriented starter policies for common governance profiles | `policyaware policy packs`, `copy_policy_pack` |
| HTTP sidecar | Let non-Python services call PolicyAware over local HTTP | `policyaware up`, `PolicyAwareSidecar` |
| Sidecar auth and security boundaries | Run PolicyAware as an authenticated out-of-process control point | `policyaware up --require-auth` |
| Dynamic policy distribution | Load central policies from file, HTTP(S), AWS S3, Google Cloud Storage, or ADLS Gen2, refresh on a TTL, cache last known-good policy, and fail closed | `Gateway.from_policy_source`, `policyaware policy pull` |
| Dynamic policy retry protection | Prevent central policy retry storms with fetch timeouts, exponential backoff, and jitter | `DynamicPolicyEngine`, `policyaware up --policy-timeout-seconds` |
| Policy composition | Compose global, compliance, region, tenant, app, and local policy layers with deny-wins override semantics | `PolicyComposer`, `policyaware policy compose` |
| Stateful session governance | Track cumulative sensitive data and repeated tool calls across a conversation or agent run | `SessionStateMonitor`, `policyaware up --session-state` |
| Enterprise hardening | Add SQLite state, emergency revoke lists, checksum pinning, and signed audit traces | `SQLiteSessionStateStore`, `EmergencyRevokeList`, `IntegritySigner` |
| Policy rollout and trace correlation | Shadow/canary candidate policies, parent trace IDs, session IDs, and governance dashboards | `PolicyRollout`, `GovernanceDashboard` |
| Observability templates | Connect PolicyAware outputs to Grafana, Prometheus, OTel, SIEM, and GRC workflows | `examples/observability` |
| Policy contract checks | Prevent drift between YAML tool policy and Python tool signatures | `PolicyContractChecker`, `policyaware contract check` |

## Capability Guides

- [Data Protection](capabilities/data-protection.md)
- [Ready-To-Use YAML Policies](capabilities/ready-to-use-yaml.md)
- [YAML Policy Templates](yaml-policy-templates.md)
- [Policy Enforcement](capabilities/policy-enforcement.md)
- [Gateway Orchestration](capabilities/gateway-orchestration.md)
- [Risk Classification](capabilities/risk-classification.md)
- [Model Routing And Providers](capabilities/model-routing-providers.md)
- [Provider Adapter Examples](provider-adapter-examples.md)
- [Usage Modes](usage-modes.md)
- [Enterprise Readiness](enterprise-readiness.md)
- [Limitations And Scope](limitations.md)
- [Security Model](security-model.md)
- [Security Boundaries](security-boundaries.md)
- [Examples Matrix](examples-matrix.md)
- [Compatibility And Integration Status](compatibility.md)
- [Tool Governance](capabilities/tool-governance.md)
- [Evaluation](capabilities/evaluation.md)
- [Audit And Observability](capabilities/audit-observability.md)
- [ML-Assisted Signals](capabilities/ml-assisted-signals.md)
- [Local Code Scan](local-code-scan.md)
- [Guardrails Integrations](capabilities/guardrails-integrations.md)
- [LangChain And LlamaIndex Callback Integrations](capabilities/integration-callbacks.md)
- [LangGraph Integration](capabilities/langgraph-integration.md)
- [Haystack Integration](capabilities/haystack-integration.md)
- [Microsoft AGT-Style Interop](capabilities/microsoft-agt-interop.md)
- [Integration Recommender](capabilities/integration-recommender.md)
- [CLI Usability Commands](cli-usability.md)
- [Policy Packs](policy-packs.md)
- [HTTP Sidecar Gateway](sidecar-http-gateway.md)
- [Dynamic Policy Distribution](dynamic-policy-distribution.md)
- [Policy Composition](policy-composition.md)
- [Stateful Session Governance](stateful-session-governance.md)
- [Enterprise Hardening](enterprise-hardening.md)
- [Policy Rollout And Trace Correlation](policy-rollout-and-trace-correlation.md)
- [Observability Templates](observability-templates.md)
- [Policy Contract Checks](policy-contract-checks.md)
- [Integration Strategy](integrations-strategy.md)
- [Lightweight Benchmarks](benchmarks.md)

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
| [Audit And Observability](capabilities/audit-observability.md) | Main APIs, `AuditTrace` fields, exporter APIs, blocked-action telemetry attributes |
| [ML-Assisted Signals](capabilities/ml-assisted-signals.md) | Main APIs, `MLSignal` fields, YAML policy fields |
| [Local Code Scan](local-code-scan.md) | Main APIs, `ScanFinding` fields, scan config YAML, CLI output formats |
| [Guardrails Integrations](capabilities/guardrails-integrations.md) | Main APIs, `GuardrailResult` fields, optional extras, adapter examples |
| [LangChain And LlamaIndex Callback Integrations](capabilities/integration-callbacks.md) | Main APIs, callback event methods, `PolicyAwareCallbackResult` fields, YAML example |
| [LangGraph Integration](capabilities/langgraph-integration.md) | Main APIs, node/state guard examples, tool-call governance YAML |
| [Haystack Integration](capabilities/haystack-integration.md) | Main APIs, RAG query guard, output evaluator, tool governance component, YAML example |
| [Microsoft AGT-Style Interop](capabilities/microsoft-agt-interop.md) | Main APIs, evidence JSON fields, tool-governance YAML, agent evidence export example |
| [Integration Recommender](capabilities/integration-recommender.md) | Main APIs, CLI examples, detected project signals, recommendation output schema |
| [CLI Usability Commands](cli-usability.md) | Doctor checks, example runner, HTML recommendation report, conservative policy migration |
| [Policy Packs](policy-packs.md) | Pack list/copy/show commands, included starter policies, Python API |
| [HTTP Sidecar Gateway](sidecar-http-gateway.md) | Endpoints, curl examples, non-Python service pattern, structured rejection payloads |
| [Security Boundaries](security-boundaries.md) | Embedded SDK vs authenticated sidecar/gateway deployment guidance |
| [Dynamic Policy Distribution](dynamic-policy-distribution.md) | Central file, HTTP(S), S3, GCS, or ADLS Gen2 policy source, refresh interval, cache, and emergency revoke pattern |
| [Policy Composition](policy-composition.md) | Hierarchical policy layers, explicit deny-wins behavior, and time-bound local exceptions |
| [Stateful Session Governance](stateful-session-governance.md) | Cumulative leakage and repeated tool-call detection across a session |
| [Enterprise Hardening](enterprise-hardening.md) | SQLite state, emergency revokes, checksum pinning, signed audit traces |
| [Policy Rollout And Trace Correlation](policy-rollout-and-trace-correlation.md) | Shadow/canary rollout, parent trace/session IDs, dashboard |
| [Observability Templates](observability-templates.md) | Grafana, Prometheus, OpenTelemetry, SIEM/GRC export pattern |
| [Policy Contract Checks](policy-contract-checks.md) | Contract drift checks, naming conventions, CI gate examples |

## Recommended Learning Path

1. Start with `DataProtectionEngine` for simple string checks.
2. Add a YAML policy and test `PolicyEngine`.
3. Use `Gateway` for complete request handling.
4. Add `RiskClassifier`, `ModelRouter`, and audit storage.
5. Add tool governance for agents.
6. Run `policyaware scan .` to find governance and compliance gaps in local code.
7. Use policy packs and policy composition when multiple teams own different policy layers.
8. Add dynamic policy distribution when many services need central policy updates.
9. Add optional ML signals only after the rules-based path is understood.

## Feedback And User Stories

PolicyAware improves through real-world user feedback.

- Private structured feedback form: https://docs.google.com/forms/d/e/1FAIpQLSc2QcQydjXZ0YF9bbVSpudoM5y8noxIP5jU-acVmjlyvf6Slg/viewform
- Public GitHub Discussions: https://github.com/ktirupati/policyaware/discussions
- Testimonials and Show and Tell: https://github.com/ktirupati/policyaware/discussions/categories/show-and-tell

Please do not share secrets, private prompts, PHI, PII, customer data, or confidential internal details.
