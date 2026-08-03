# Observability Templates

PolicyAware emits audit traces, Prometheus-style metrics, OpenTelemetry-shaped JSON, HTML reports, JSON reports, SARIF, and Markdown outputs.

These templates help teams connect PolicyAware evidence to existing monitoring and compliance systems.

## Files

- `grafana-dashboard.json`
- `otel-collector-config.yaml`
- `prometheus-policyaware.yml`

## Generate Metrics Locally

```bash
policyaware observability prometheus .policyaware/traces.jsonl --out .policyaware/metrics.prom
policyaware observability otel-json .policyaware/traces.jsonl --out .policyaware/otel-spans.json
```

Use these as starting points for your own Grafana, Prometheus, OpenTelemetry Collector, SIEM, or GRC pipeline.
