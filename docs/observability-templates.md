# Observability Templates

PolicyAware emits audit traces, HTML reports, JSON reports, SARIF, Markdown reports, Prometheus-style metrics, OpenTelemetry-shaped JSON, and live runtime metrics from the HTTP sidecar.

The repository includes templates that help teams connect PolicyAware evidence to existing dashboards and compliance systems.

## Template Files

```text
examples/observability/grafana-dashboard.json
examples/observability/otel-collector-config.yaml
examples/observability/prometheus-policyaware.yml
```

## Generate Local Metrics

```bash
policyaware observability prometheus .policyaware/traces.jsonl --out .policyaware/metrics.prom
policyaware observability otel-json .policyaware/traces.jsonl --out .policyaware/otel-spans.json
```

## Live Runtime Metrics

The sidecar exposes a Prometheus-compatible metrics endpoint:

```bash
policyaware up --policy policyaware.yaml --tool-policy tool-governance.yaml --port 8080
curl http://127.0.0.1:8080/metrics
```

If sidecar auth is enabled, pass the same bearer token used for policy endpoints:

```bash
curl http://127.0.0.1:8080/metrics \
  -H "Authorization: Bearer replace-with-secret-token"
```

Use this endpoint with Prometheus, Grafana Agent, OpenTelemetry Collector
Prometheus receiver, Datadog Agent OpenMetrics checks, or another enterprise
metrics pipeline.

## Native Runtime Metrics

PolicyAware records enforcement telemetry as requests and tool checks happen.
Important built-in metrics include:

```text
policyaware_requests_total
policyaware_policy_decisions_total{decision="deny"}
policyaware_policy_denied_total
policyaware_approval_required_total
policyaware_redactions_total
policyaware_reason_codes_total
policyaware_model_route_total
policyaware_latency_ms_sum
policyaware_latency_ms_count
policyaware_tool_decisions_total
policyaware_tool_denied_total
policyaware_tool_approval_required_total
policyaware_eval_failures_total
```

Common labels include:

```text
tenant
app
decision
risk_tier
model
connector_id
action
reason_code
```

## Python API

```python
from policyaware import Gateway, GatewayRequest, RuntimeTelemetryCollector

telemetry = RuntimeTelemetryCollector()
gateway = Gateway.from_policy_file("policyaware.yaml")
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

## Suggested Enterprise Pattern

```mermaid
flowchart LR
    A["PolicyAware Gateway / Scan / Sidecar"] --> B["Audit Traces"]
    A --> C["/metrics Prometheus Endpoint"]
    A --> D["OpenTelemetry-Shaped Events"]
    B --> E["SIEM / GRC"]
    C --> F["Prometheus / Grafana"]
    D --> G["OpenTelemetry Collector / Datadog / SIEM"]
```

## What To Dashboard

- policy decisions by allow/deny/approval/redact
- risk tier counts
- PII/PHI/secrets detections
- tool approvals and denials
- model/provider usage
- estimated cost
- scan findings by severity
- eval failures

PolicyAware does not force a single dashboard. It gives teams portable evidence that can be used with their existing observability, SIEM, and compliance tools.
