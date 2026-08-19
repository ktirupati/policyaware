# HTTP Sidecar Gateway

PolicyAware is Python-first, but non-Python services can use it through a lightweight HTTP sidecar.

The sidecar is dependency-free and uses Python's standard library HTTP server. It is intended as a local service, sidecar, or internal gateway pattern for Node.js, Go, Java, Rust, and other application stacks.

Use embedded SDK mode when you want fast adoption inside a Python app. Use sidecar or gateway mode when you want a stronger out-of-process enforcement point with separate runtime identity, network policy, logs, and operational controls.

## Start The Sidecar

```bash
policyaware up --policy policyaware.yaml --tool-policy tool-governance.yaml --port 8080
```

Recommended enterprise startup:

```bash
set POLICYAWARE_SIDECAR_TOKEN=replace-with-secret-token
policyaware up \
  --policy policyaware.yaml \
  --tool-policy tool-governance.yaml \
  --host 127.0.0.1 \
  --port 8080 \
  --require-auth
```

Central policy URL startup:

```bash
set POLICYAWARE_POLICY_TOKEN=replace-with-policy-source-token
policyaware up \
  --policy-url https://policy.internal.example.com/policyaware.yaml \
  --tool-policy tool-governance.yaml \
  --policy-refresh-seconds 30 \
  --policy-timeout-seconds 5 \
  --policy-retry-base-seconds 1 \
  --policy-retry-max-seconds 60 \
  --policy-retry-jitter-seconds 0.25 \
  --policy-cache .policyaware/policy-cache.yaml \
  --fallback-policy examples/policies/emergency-fallback-deny.yaml \
  --require-auth
```

ADLS Gen2 policy source:

```bash
pip install "policyaware[azure]"

policyaware up \
  --policy-url abfss://policy-configs@acmeai.dfs.core.windows.net/prod/policyaware.yaml \
  --policy-refresh-seconds 30 \
  --policy-cache .policyaware/policy-cache.yaml \
  --fallback-policy examples/policies/emergency-fallback-deny.yaml \
  --require-auth
```

AWS S3 policy source:

```bash
pip install "policyaware[providers]"

policyaware up \
  --policy-url s3://policy-configs/prod/policyaware.yaml \
  --policy-refresh-seconds 30 \
  --policy-cache .policyaware/policy-cache.yaml \
  --fallback-policy examples/policies/emergency-fallback-deny.yaml \
  --require-auth
```

Google Cloud Storage policy source:

```bash
pip install "policyaware[gcp]"

policyaware up \
  --policy-url gs://policy-configs/prod/policyaware.yaml \
  --policy-refresh-seconds 30 \
  --policy-cache .policyaware/policy-cache.yaml \
  --fallback-policy examples/policies/emergency-fallback-deny.yaml \
  --require-auth
```

Health check:

```bash
curl http://127.0.0.1:8080/health
```

Prometheus metrics:

```bash
curl http://127.0.0.1:8080/metrics
```

With sidecar auth:

```bash
curl http://127.0.0.1:8080/metrics \
  -H "Authorization: Bearer replace-with-secret-token"
```

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Liveness check. |
| `GET /metrics` | Prometheus-compatible runtime policy and tool-governance metrics. |
| `POST /v1/check` | Run prompt/context through PolicyAware Gateway. |
| `POST /v1/tool/check` | Check MCP-style connector/action permissions. |
| `POST /v1/route` | Return policy-aware route decision. |
| `POST /v1/evaluate` | Evaluate output text for leakage and configured checks. |

## Authentication

When `POLICYAWARE_SIDECAR_TOKEN` or `--auth-token` is set, all `POST` endpoints require:

```text
Authorization: Bearer replace-with-secret-token
```

`GET /health` remains unauthenticated so container orchestrators and service meshes can perform liveness checks. `GET /metrics` uses the same bearer token when sidecar auth is enabled. Use `--require-auth` in production-like environments so the sidecar fails startup if no token is configured.

## Runtime Metrics

The sidecar records live metrics for prompt checks and tool checks. These metrics
are designed for Prometheus, Grafana, OpenTelemetry Collector Prometheus
receivers, Datadog Agent OpenMetrics checks, SIEM pipelines, or GRC reporting.

Important metrics:

```text
policyaware_requests_total
policyaware_policy_decisions_total{decision="deny"}
policyaware_policy_denied_total
policyaware_approval_required_total
policyaware_redactions_total
policyaware_model_route_total
policyaware_tool_decisions_total
policyaware_tool_denied_total
policyaware_tool_approval_required_total
policyaware_eval_failures_total
```

Example Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: policyaware-sidecar
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:8080"]
```

## Cold-Start Fallback Policy

For dynamic policy URLs, use a cache and a restrictive local fallback policy:

```bash
policyaware up \
  --policy-url s3://policy-configs/prod/policyaware.yaml \
  --policy-cache .policyaware/policy-cache.yaml \
  --fallback-policy examples/policies/emergency-fallback-deny.yaml \
  --require-auth
```

Startup resolution order:

```text
remote source -> last known-good cache -> local emergency fallback -> fail closed
```

The fallback policy should deny by default and only contain emergency-safe rules.
The bundled `examples/policies/emergency-fallback-deny.yaml` denies all requests
if neither the remote policy nor the last known-good cache can be loaded.

Dynamic policy refreshes also use strict fetch timeouts and exponential backoff
with jitter. This prevents many sidecar replicas from retrying a slow HTTP/S3/GCS
or ADLS policy source on every request.

## Prompt Check

```bash
curl -X POST http://127.0.0.1:8080/v1/check \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer replace-with-secret-token" \
  -d '{
    "tenant": "acme",
    "app": "node-service",
    "user": {"id": "u_123", "role": "support_agent"},
    "context": {"region": "us", "risk": "low", "task_type": "support"},
    "prompt": "Email jane@example.com about this support case."
  }'
```

## Tool Check

```bash
curl -X POST http://127.0.0.1:8080/v1/tool/check \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer replace-with-secret-token" \
  -d '{
    "agent_id": "support_agent_1",
    "connector_id": "crm",
    "action": "update_customer",
    "tenant": "acme",
    "user": {"role": "support_agent"},
    "arguments": {"customer_id": "cust_123"}
  }'
```

## Blocked Action Rejection Handshake

When PolicyAware denies a request or requires approval, the sidecar keeps the
normal response fields and also adds a structured `rejection` object. API
routers should log this object to tracing/SIEM and return it to the caller
instead of replacing it with a vague `403 Forbidden`.

Example denied prompt response:

```json
{
  "allowed": false,
  "decision": "deny",
  "reason": "Matched rule block_secrets",
  "reason_codes": ["DATA.SECRETS_DETECTED"],
  "matched_rules": ["block_secrets"],
  "risk_tier": "high",
  "trace_id": "trc_123",
  "content": "",
  "rejection": {
    "schema_version": "0.4",
    "blocked": true,
    "status_code": 403,
    "decision": "deny",
    "reason": "Matched rule block_secrets",
    "reason_codes": ["DATA.SECRETS_DETECTED"],
    "matched_rules": ["block_secrets"],
    "trace_id": "trc_123",
    "risk_tier": "high",
    "approval_required": false
  }
}
```

Example approval-gated tool response:

```json
{
  "allowed": false,
  "decision": "require_approval",
  "approval_required": true,
  "connector_id": "github",
  "action": "create_pr",
  "rejection": {
    "blocked": true,
    "status_code": 202,
    "decision": "require_approval",
    "connector_id": "github",
    "action": "create_pr",
    "approval_required": true,
    "matched_rules": ["github.create_pr"]
  }
}
```

FastAPI route pattern:

```python
import logging

from fastapi import FastAPI
from policyaware import Gateway, GatewayRequest, policy_rejection

app = FastAPI()
gateway = Gateway.from_policy_file("policyaware.yaml")
logger = logging.getLogger("policyaware")


@app.post("/chat")
def chat(body: dict):
    response = gateway.chat(
        GatewayRequest(
            tenant=body.get("tenant", "default"),
            app="support-api",
            user=body.get("user", {"role": "anonymous"}),
            context=body.get("context", {}),
            messages=[{"role": "user", "content": body["prompt"]}],
        )
    )
    rejection = policy_rejection(response)
    if rejection:
        # Send this object to OpenTelemetry, SIEM, or your central logger.
        logger.warning("policyaware_rejection", extra=rejection.model_dump(mode="json"))
        return {
            "error": "policyaware_rejection",
            "rejection": rejection.model_dump(mode="json"),
        }
    return {"content": response.content, "trace_id": response.trace_id}
```

## Python API

```python
from policyaware import Gateway, PolicyAwareSidecar

sidecar = PolicyAwareSidecar(Gateway.from_policy_file("policyaware.yaml"))
status, payload = sidecar.handle("POST", "/v1/check", {"prompt": "Summarize this ticket."})
print(status, payload["decision"])
```

Protected sidecar example:

```python
from policyaware import Gateway, PolicyAwareSidecar

sidecar = PolicyAwareSidecar(
    Gateway.from_policy_file("policyaware.yaml"),
    auth_token="replace-with-secret-token",
)

status, payload = sidecar.handle(
    "POST",
    "/v1/check",
    {"prompt": "Email jane@example.com"},
    headers={"Authorization": "Bearer replace-with-secret-token"},
)

print(status, payload["decision"])
```

## Security Boundary Guidance

An embedded SDK is not a hard isolation boundary. If an attacker achieves Remote Code Execution inside the same application process, they may be able to bypass local checks, alter application flow, or disable logging.

For higher-assurance deployments, run PolicyAware out of process:

```mermaid
flowchart LR
    A["Application Service"] --> B["Authenticated PolicyAware Sidecar"]
    B --> C["Policy / Data Protection / Tool Governance"]
    C --> D["Approved Model Or Tool"]
    C --> E["Audit / Metrics / SIEM"]
```

Recommended controls:

- Keep the sidecar on a private interface, private subnet, service mesh, or internal API gateway.
- Require bearer auth using `POLICYAWARE_SIDECAR_TOKEN` and `--require-auth`.
- Run the sidecar with a separate service identity and minimal file/network permissions.
- Place TLS, mTLS, WAF/API gateway rules, IAM, and network policy outside the sidecar.
- Export audit and metrics to a central observability, SIEM, or GRC system.
- Treat PolicyAware as an AI governance control plane, not a replacement for secure runtime design.

## Production Notes

- Put authentication, authorization, TLS, and network policy in front of the sidecar.
- Do not expose the sidecar directly to the public internet.
- Use your platform's normal service mesh, API gateway, or internal ingress controls.
- Export audit traces and metrics to your existing observability/SIEM/GRC systems.
