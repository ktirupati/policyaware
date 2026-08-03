# Security Boundaries

PolicyAware provides AI governance controls for prompts, context, model routing, MCP/tool calls, evaluations, local code scans, and audit evidence.

It should be deployed with the same security discipline as any other control-plane component.

## Embedded SDK Mode

Embedded SDK mode runs inside your Python application process:

```python
from policyaware import Gateway

gateway = Gateway.from_policy_file("policyaware.yaml")
```

This is the fastest adoption path and works well for Python applications, local development, CI tests, RAG pipelines, agent prototypes, and application-owned policy checks.

Important boundary: embedded SDK mode is not a hard security boundary. If an attacker achieves Remote Code Execution inside the same Python process, they may be able to bypass local checks or alter application control flow.

## Sidecar / Gateway Mode

Sidecar mode runs PolicyAware out of process:

```bash
set POLICYAWARE_SIDECAR_TOKEN=replace-with-secret-token
policyaware up --policy policyaware.yaml --tool-policy tool-governance.yaml --require-auth
```

Applications call it before model or tool execution:

```bash
curl -X POST http://127.0.0.1:8080/v1/check \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer replace-with-secret-token" \
  -d '{"prompt": "Email jane@example.com"}'
```

This is the stronger enterprise pattern because PolicyAware can run with separate process memory, service identity, deployment lifecycle, audit stream, private network access, and service mesh or API gateway controls.

## Recommended Enterprise Pattern

```mermaid
flowchart LR
    A["App / Agent / RAG Service"] --> B["Private Network / Service Mesh"]
    B --> C["PolicyAware Sidecar Or Internal Gateway"]
    C --> D["Model Provider"]
    C --> E["MCP Tool Connector"]
    C --> F["Audit / Metrics / SIEM / GRC"]
```

Use PolicyAware with IAM, least-privilege service accounts, TLS or mTLS, private networking, secret management for `POLICYAWARE_SIDECAR_TOKEN`, centralized logs, and CI checks for policy schema, policy/tool contract drift, and local code scan findings.

## What PolicyAware Is Not

PolicyAware is not a replacement for application security testing, sandboxing, WAF/API gateway controls, IAM, secrets management, container isolation, endpoint detection and response, or secure SDLC.

PolicyAware is the AI governance layer that helps decide whether an AI request, tool call, model route, or response should be allowed, denied, redacted, escalated, evaluated, and audited.

