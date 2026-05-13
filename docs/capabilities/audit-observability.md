# Audit And Observability

## What It Does

Audit captures evidence for policy decisions and runtime behavior.

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
from policyaware import AuditLogger, SQLiteAuditLogger, TraceViewer, AuditBundleWriter
```

## Main APIs

| API | Type | What It Does |
| --- | --- | --- |
| `AuditLogger(path)` | class | Writes and reads JSONL audit traces. |
| `SQLiteAuditLogger(path)` | class | Writes persistent audit traces to SQLite. |
| `logger.read_traces()` | method | Reads stored traces. |
| `logger.find_trace(trace_id)` | method | Finds one trace by ID. |
| `TraceViewer().write_html(...)` | method | Generates a local HTML trace viewer. |
| `AuditBundleWriter().write(...)` | method | Generates compliance evidence artifacts for a trace. |
| `PrometheusExporter` | class | Exports trace metrics in Prometheus format. |
| `OpenTelemetryJsonExporter` | class | Exports OpenTelemetry-shaped JSON from traces. |

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
