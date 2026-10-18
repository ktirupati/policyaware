# Audit And Observability

## What It Does

Audit captures evidence for policy decisions and runtime behavior.

These records document what PolicyAware observed and decided. They are technical evidence for downstream review, not immutable proof, legal conclusions, or a complete audit program. Configure access control, integrity protection, export, and retention in the deployment that stores them.

Audit bundles and traces are not automatically cross-walked to NIST AI RMF, ISO/IEC 42001, or EU AI Act controls, and they are not a formal compliance assessment. Teams must define and review their own control mappings, evidence sufficiency, retention, and legal interpretation. PolicyAware does not certify that an organization is compliant. See [Capabilities, Boundaries, And Deployment Choices](../capability-boundaries.md).

Decisions from `PolicyEngine`, `ToolPolicyEngine`, and `EmergencyRevokeList` carry the policy ID, optional human-managed `policy_version`, schema version, and SHA-256 fingerprint of the canonical configuration. Audit traces preserve these fields when the recorded decision came from one of those engines. Session-threshold decisions may not have a policy fingerprint. The fingerprint identifies configuration content; it is not a digital signature or proof of who approved or published it.

PolicyAware's observability features focus on governance events and policy evidence. They do not replace a dedicated LLM observability platform for detailed trace exploration, experiment comparison, production quality analytics, cohort analysis, or drift diagnosis. Export or correlate PolicyAware traces with the observability stack already used by your team when those capabilities are needed.

It records:

- trace ID
- request ID
- tenant
- app
- user ID
- policy decision
- matched rules
- reason codes
- risk tier
- selected model
- latency
- eval scores
- request/response snapshots

## Imports

```python
from policyaware import (
    AuditBundleWriter,
    AuditLogger,
    RuntimeTelemetryCollector,
    SQLiteAuditLogger,
    TraceViewer,
)
```

## Main APIs

| API | Type | What It Does |
| --- | --- | --- |
| `AuditLogger(path)` | class | Writes and reads JSONL audit traces. |
| `SQLiteAuditLogger(path)` | class | Writes persistent audit traces to SQLite. |
| `logger.read_traces()` | method | Reads stored traces. |
| `logger.find_trace(trace_id)` | method | Finds one trace by ID. |
| `TraceViewer().write_html(...)` | method | Generates a local HTML trace viewer. |
| `AuditBundleWriter().write(...)` | method | Generates technical audit evidence artifacts for downstream governance review; it does not map them to regulatory controls. |
| `PrometheusExporter` | class | Exports trace metrics in Prometheus format. |
| `OpenTelemetryJsonExporter` | class | Exports OpenTelemetry-shaped JSON from traces. |
| `RuntimeTelemetryCollector` | class | Records live request and tool-governance metrics for runtime dashboards. |
| `RuntimeTelemetryCollector.record_governance_event(...)` | method | Records advanced governance events such as jury vetoes, trajectory mutation, synthetic redaction, retrieval sanitization, and circuit-breaker pauses. |

## Policy Provenance

Add an optional revision to a policy file. The content fingerprint is computed automatically and is attached to `PolicyDecision`, `ToolDecision`, and `AuditTrace` results.

```yaml
id: customer-support-policy
policy_version: "2026.10.1"
schema_version: "0.4"
default: deny
rules:
  - name: allow_low_risk_support
    effect: allow
    when:
      user.role_in: [support_agent]
      risk.tier: low
```

Use `policy_sha256` to compare the effective policy content across deployments. Formatting-only YAML changes do not change the fingerprint; content changes do. `policy_version` is a human-managed revision label, while `schema_version` describes the policy schema.

Print the same runtime provenance from the CLI for release records or CI artifacts:

```bash
policyaware policy fingerprint policyaware.yaml --json
policyaware policy fingerprint policyaware.yaml --expected-sha256 <approved-sha256> --json
```

The command validates the policy first. With `--expected-sha256`, CI receives a nonzero exit code when the current fingerprint differs from the approved value. Its SHA-256 identifies the parsed policy content; it is not a digital signature or approval attestation.

For a reviewable pin tracked with policy code, create and verify a lockfile:

```bash
policyaware policy lock create policyaware.yaml --out policyaware.lock.json
policyaware policy lock verify policyaware.yaml --lock-file policyaware.lock.json --json
```

The lockfile is unsigned; protect it through the same repository review and access controls as the policy itself.

## Snapshot Privacy

Audit snapshots default to `full` for backward compatibility. This mode can store prompts, outputs, context, metadata, and tool arguments. Select `metadata` to omit those free-text and arbitrary payload snapshots while keeping a request ID and compact policy decision data:

```python
from policyaware import AuditLogger, Gateway

gateway = Gateway.from_policy_file("policyaware.yaml")
gateway.audit_logger = AuditLogger(
    ".policyaware/traces.jsonl",
    snapshot_mode="metadata",
)
```

SQLite supports the same option:

```python
from policyaware import SQLiteAuditLogger

gateway.audit_logger = SQLiteAuditLogger(
    ".policyaware/audit.db",
    snapshot_mode="metadata",
)
```

Metadata mode still records normal trace-level identifiers and governance fields, including tenant, app, user ID, and session ID when supplied. Prefer opaque identifiers and apply access controls and retention limits to audit storage. Full mode intentionally retains payload snapshots; do not enable it without reviewing data classification, access, and retention requirements.

## `AuditTrace` Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `trace_id` | `str` | Unique trace identifier. |
| `request_id` | `str` | Request identifier from `GatewayRequest`. |
| `tenant` | `str` | Tenant boundary. |
| `app` | `str` | Calling application. |
| `user_id` | `str \| None` | User ID when supplied. |
| `task_type` | `str \| None` | Task type from request context. |
| `policy_decision` | `str` | Final policy decision. |
| `matched_rules` | `list[str]` | Policy rules that matched. |
| `reason_codes` | `list[str]` | Machine-readable reason codes. |
| `actions` | `list[str]` | Enforcement actions, such as redaction. |
| `risk_tier` | `str` | Risk tier recorded for audit. |
| `model` | `str \| None` | Selected model when a provider was called. |
| `input_tokens` | `int` | Estimated input tokens. |
| `output_tokens` | `int` | Estimated output tokens. |
| `estimated_cost_usd` | `float` | Estimated request cost. |
| `latency_ms` | `int` | Request latency in milliseconds. |
| `risk_score` | `float` | Numeric risk score. |
| `eval_scores` | `dict` | Runtime evaluation scores. |
| `request_snapshot` | `dict` | Captured request metadata. |
| `response_snapshot` | `dict` | Captured response metadata. |
| `tool_calls` | `list[dict]` | Tool-call audit entries when present. |
| `created_at` | `datetime` | Trace creation timestamp. |

## JSONL Audit

```python
from policyaware import AuditLogger, Gateway, GatewayRequest

gateway = Gateway.from_policy_file("examples/policies/basic.yaml")
gateway.audit_logger = AuditLogger(".policyaware/traces.jsonl")

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="demo",
        user={"id": "u1", "role": "support_agent"},
        context={"region": "us", "risk": "low"},
        messages=[{"role": "user", "content": "Summarize this ticket."}],
    )
)

print(response.trace_id)
```

## SQLite Audit

```python
from policyaware import SQLiteAuditLogger

gateway.audit_logger = SQLiteAuditLogger(".policyaware/audit.db")
```

## Trace Viewer

```python
from policyaware import AuditLogger, TraceViewer

traces = AuditLogger(".policyaware/traces.jsonl").read_traces()
TraceViewer().write_html(traces, ".policyaware/trace-viewer.html")
```

## Audit Bundle

```python
from policyaware import AuditBundleWriter, AuditLogger

logger = AuditLogger(".policyaware/traces.jsonl")
trace = logger.find_trace("trc_example")
AuditBundleWriter().write(trace, ".policyaware/audit-bundle")
```

## CLI

```bash
policyaware audit view .policyaware/traces.jsonl --out .policyaware/trace-viewer.html
policyaware audit bundle trc_example --traces-file .policyaware/traces.jsonl
policyaware observability prometheus .policyaware/traces.jsonl
policyaware observability otel-json .policyaware/traces.jsonl
```

## Runtime Metrics

PolicyAware also records live runtime telemetry in the gateway and sidecar. This
is useful when compliance, platform, or security teams want dashboard-ready
signals without parsing JSONL logs across many clusters.

```python
from policyaware import Gateway, GatewayRequest, RuntimeTelemetryCollector

telemetry = RuntimeTelemetryCollector()
gateway = Gateway.from_policy_file("examples/policies/basic.yaml")
gateway.telemetry = telemetry

gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="support-copilot",
        user={"id": "u1", "role": "support_agent"},
        context={"region": "us", "risk": "low", "task_type": "support"},
        messages=[{"role": "user", "content": "Email jane@example.com"}],
    )
)

print(telemetry.prometheus_text())
print(telemetry.otel_events())
```

Use native OpenTelemetry when your application already configures an OTel SDK
and exporter:

```bash
pip install "policyaware[observability]"
```

```python
from policyaware import OpenTelemetryBridge, RuntimeTelemetryCollector

telemetry = RuntimeTelemetryCollector(
    otel_bridge=OpenTelemetryBridge("policyaware.claims-assistant")
)
```

Record an advanced governance event:

```python
telemetry.record_governance_event(
    event_type="trajectory_mutation",
    tenant="acme",
    app="agent-platform",
    decision="conditional_allow",
    blocked=False,
    attributes={
        "policyaware.mutation": "safe_rewrite",
        "policyaware.reason": "removed sensitive instruction",
    },
)
```

OpenTelemetry-shaped runtime events include blocked-action attributes such as:

```json
{
  "name": "policyaware.gateway.request",
  "attributes": {
    "policyaware.decision": "deny",
    "policyaware.blocked": true,
    "policyaware.reason_codes": ["DATA.SECRETS_DETECTED"],
    "policyaware.matched_rules": ["block_secrets"],
    "policyaware.trace_id": "trc_123"
  }
}
```

Tool-governance events also include `policyaware.connector_id`,
`policyaware.action`, `policyaware.approval_required`, and
`policyaware.blocked`. Use these fields for alerts such as "blocked tool call",
"approval required", or "secret leakage attempt".

The HTTP sidecar exposes the same metrics at:

```bash
curl http://127.0.0.1:8080/metrics
```

Important metric names:

```text
policyaware_requests_total
policyaware_policy_decisions_total
policyaware_policy_denied_total
policyaware_approval_required_total
policyaware_redactions_total
policyaware_model_route_total
policyaware_tool_decisions_total
policyaware_tool_denied_total
policyaware_tool_approval_required_total
policyaware_eval_failures_total
policyaware_governance_events_total
policyaware_governance_blocked_total
```
