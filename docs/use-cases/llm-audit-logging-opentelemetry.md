# LLM Audit Logging And OpenTelemetry

PolicyAware emits structured policy decisions, blocked-action payloads, Prometheus-style metrics, and OpenTelemetry-shaped events so teams can send AI governance signals to existing observability, SIEM, GRC, or audit systems.

This page is for searches like OpenTelemetry hookups for blocked AI actions, LLM audit logging Python, and policy denied metrics for AI agents.

## Install

```bash
pip install policyaware
```

## Sidecar With Metrics

```bash
policyaware up \
  --policy policyaware.yaml \
  --port 8080 \
  --require-auth \
  --metrics
```

Then fetch metrics:

```bash
curl http://localhost:8080/metrics
```

## Python Example

```python
from policyaware.observability import RuntimeTelemetryCollector
from policyaware.rejections import policy_rejection

telemetry = RuntimeTelemetryCollector()

rejection = policy_rejection(
    decision="deny",
    reason_codes=["PA_POLICY_DENY", "PA_SECRET_DETECTED"],
    policy_ids=["deny-secrets-to-external-models"],
    trace_id="trace_123",
    remediation=["Remove secrets or route to an approved internal workflow."],
)

telemetry.record_policy_rejection(rejection.to_dict())

print(rejection.to_dict())
print(telemetry.to_prometheus())
```

## Example Rejection Payload

```json
{
  "decision": "deny",
  "reason_codes": ["PA_POLICY_DENY", "PA_SECRET_DETECTED"],
  "policy_ids": ["deny-secrets-to-external-models"],
  "trace_id": "trace_123",
  "remediation": ["Remove secrets or route to an approved internal workflow."],
  "blocked": true
}
```

## What To Send To Dashboards

| Signal | Why It Matters |
| --- | --- |
| `policyaware_policy_denied_total` | Tracks blocked AI actions |
| `policyaware_tool_denied_total` | Tracks blocked MCP/tool calls |
| `policyaware_approval_required_total` | Shows human-in-the-loop volume |
| `policyaware_sensitive_data_detected_total` | Shows data-protection pressure |
| `trace_id` and `session_id` | Links application traces to governance traces |

## Enterprise Pattern

1. Return structured rejection objects from API middleware.
2. Log reason codes, policy IDs, trace IDs, and remediation.
3. Export Prometheus metrics for dashboards.
4. Export OTel-shaped events for distributed tracing.
5. Archive audit bundles for compliance reviews.

## Related Documentation

- [Audit And Observability](../capabilities/audit-observability.md)
- [Observability Templates](../observability-templates.md)
- [Policy Rollout And Trace Correlation](../policy-rollout-and-trace-correlation.md)
- [HTTP Sidecar Gateway](../sidecar-http-gateway.md)
