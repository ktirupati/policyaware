# Performance, Telemetry, And Visual Simulation

PolicyAware is designed to stay lightweight for `pip install policyaware`, while
still giving enterprise teams the operational hooks they need for low-latency
governance, centralized monitoring, and developer debugging.

## High-Performance Runtime Boundary

The base package uses pure Python so developers can install and test it quickly.
PolicyAware exposes a small fast-core facade that keeps performance-sensitive
work behind a stable API:

```python
from policyaware import FastCoreRuntime

runtime = FastCoreRuntime()

payload = runtime.loads_json('{"tool": "github.delete_branch"}')
matches = runtime.find_regex(r"\b\d{3}-\d{2}-\d{4}\b", "SSN 123-45-6789")

print(runtime.status.backend)
print(runtime.status.reason)
```

Check runtime mode from the CLI:

```bash
policyaware performance status
policyaware performance status --json
```

Today, this gives a safe pure-Python runtime with a public extension point. A
future optional native accelerator can implement the same boundary through a
`policyaware_fast` module without changing application code.

## OpenTelemetry And Prometheus Exporting

PolicyAware emits:

- Prometheus-compatible metrics from the sidecar `/metrics` endpoint.
- Prometheus files from audit traces.
- OpenTelemetry-shaped JSON spans/events.
- Native OpenTelemetry span events when `opentelemetry-api` is installed and
  configured by the host application.
- Semantic governance events for advanced controls such as trajectory mutation,
  synthetic redaction, retrieval sanitization, jury vetoes, and circuit breakers.

Install the optional OTel bridge support:

```bash
pip install "policyaware[observability]"
```

```python
from policyaware import OpenTelemetryBridge, RuntimeTelemetryCollector

telemetry = RuntimeTelemetryCollector(
    otel_bridge=OpenTelemetryBridge("policyaware.agent-platform")
)

telemetry.record_governance_event(
    event_type="jury_veto",
    tenant="acme",
    app="agent-platform",
    decision="deny",
    blocked=True,
    attributes={
        "policyaware.jury.quorum": "2/3",
        "policyaware.reason": "high-risk destructive action",
    },
)

print(telemetry.prometheus_text())
print(telemetry.otel_events())
```

The same event is available in three forms:

- Prometheus counter: `policyaware_governance_events_total`
- OTel-shaped JSON event: `policyaware.governance.jury_veto`
- Native OpenTelemetry span event when an OTel SDK/exporter is configured

Export existing traces:

```bash
policyaware observability prometheus .policyaware/traces.jsonl \
  --out .policyaware/metrics.prom

policyaware observability otel-json .policyaware/traces.jsonl \
  --out .policyaware/otel-spans.json
```

Run the sidecar metrics endpoint:

```bash
policyaware up --config policyaware.yaml --port 8080
curl http://127.0.0.1:8080/metrics
```

## Visual Policy Simulator

When a prompt, tool call, or agent action is blocked, developers need a clear
answer to: which rule fired, what decision happened, and what should be changed?

Launch the interactive local dashboard:

```bash
policyaware dashboard --policy examples/policies/basic.yaml --port 8765
```

Open:

```text
http://127.0.0.1:8765
```

For FastAPI/Uvicorn mode, install the dashboard extra:

```bash
pip install "policyaware[dashboard]"
policyaware dashboard --policy policyaware.yaml --fastapi
```

If FastAPI is not installed, PolicyAware automatically falls back to a
dependency-free local web server.

Use the visual simulator to generate a local HTML explanation for one request:

```bash
policyaware dashboard simulate examples/policies/basic.yaml \
  --prompt "Email jane@example.com about this claim" \
  --role support_agent \
  --tenant acme \
  --risk low \
  --out .policyaware/policy-simulator.html
```

Open the generated report:

```bash
start .policyaware/policy-simulator.html
```

The report includes final decision, risk tier, matched rules, violated rules,
reason codes, policy actions, remediation hints, and model-safe output.

## Recommended Production Pattern

```text
Application / Agent
  -> PolicyAware gateway or sidecar
  -> RuntimeTelemetryCollector
  -> Prometheus / OpenTelemetry / SIEM
  -> audit traces and visual simulator for debugging
```

For very high-throughput deployments:

1. Keep the base package installed in application services.
2. Use `policyaware performance status` in startup diagnostics.
3. Export `/metrics` to Prometheus or an OpenTelemetry Collector.
4. Generate simulator reports for policy-debug tickets.
5. Keep heavy ML extras optional and install only where needed.
