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
  --policy-cache .policyaware/policy-cache.yaml \
  --require-auth
```

ADLS Gen2 policy source:

```bash
pip install "policyaware[azure]"

policyaware up \
  --policy-url abfss://policy-configs@acmeai.dfs.core.windows.net/prod/policyaware.yaml \
  --policy-refresh-seconds 30 \
  --policy-cache .policyaware/policy-cache.yaml \
  --require-auth
```

AWS S3 policy source:

```bash
pip install "policyaware[providers]"

policyaware up \
  --policy-url s3://policy-configs/prod/policyaware.yaml \
  --policy-refresh-seconds 30 \
  --policy-cache .policyaware/policy-cache.yaml \
  --require-auth
```

Google Cloud Storage policy source:

```bash
pip install "policyaware[gcp]"

policyaware up \
  --policy-url gs://policy-configs/prod/policyaware.yaml \
  --policy-refresh-seconds 30 \
  --policy-cache .policyaware/policy-cache.yaml \
  --require-auth
```

Health check:

```bash
curl http://127.0.0.1:8080/health
```

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Liveness check. |
| `POST /v1/check` | Run prompt/context through PolicyAware Gateway. |
| `POST /v1/tool/check` | Check MCP-style connector/action permissions. |
| `POST /v1/route` | Return policy-aware route decision. |
| `POST /v1/evaluate` | Evaluate output text for leakage and configured checks. |

## Authentication

When `POLICYAWARE_SIDECAR_TOKEN` or `--auth-token` is set, all `POST` endpoints require:

```text
Authorization: Bearer replace-with-secret-token
```

`GET /health` remains unauthenticated so container orchestrators and service meshes can perform liveness checks. Use `--require-auth` in production-like environments so the sidecar fails startup if no token is configured.

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
