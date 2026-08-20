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

## Execution-Plane Memory Boundary

PolicyAware is an AI governance control plane. It decides whether requests, prompts, model routes, tool calls, and outputs should be allowed, denied, redacted, escalated, evaluated, and audited.

It is not a secure-memory runtime. It does not guarantee encrypted in-memory Python objects, `mlock`-style page locking, `explicit_bzero`-style memory wiping, or protection from a malicious dependency that already has code execution inside the same process.

Recommended pattern:

- Keep raw secrets out of prompts and tool arguments.
- Prefer short-lived credentials and scoped tokens.
- Use secret managers instead of passing long-lived keys through agent state.
- Use sidecar or gateway mode to reduce shared process exposure.
- Clear application references to sensitive objects when practical, without claiming hard memory erasure.
- Harden containers, scan dependencies, and maintain SBOMs for high-risk environments.

## Execution Sandboxing Boundary

PolicyAware can block, allow, or require approval before a tool executes. It does not natively execute approved tools inside Docker, Wasm, gVisor, Firecracker, or another sandbox.

If an approved tool runs with broad host privileges, the operating system privilege boundary is owned by the application platform, not by the PolicyAware policy decision.

Recommended pattern:

- Run risky tools with least-privilege service accounts.
- Separate read-only tools from write/delete/deploy/payment tools.
- Use container, Wasm, gVisor, Firecracker, or Kubernetes job isolation for untrusted execution.
- Require approval for destructive or external-impact actions.
- Keep tool credentials scoped to the minimum action, tenant, and lifetime.
- Audit tool decisions and execution results together.

## Semantic Governance Boundary

PolicyAware's core enforcement path is deterministic and explainable. It evaluates YAML policies, structured context, risk tiers, data-protection findings, tool/action metadata, budget limits, routing rules, and evaluation results.

This makes decisions auditable, but it is not the same as native semantic understanding. Sophisticated prompt injection, implied policy violations, social engineering, or domain-specific misuse may not trigger an exact rule unless teams add stronger signals.

Recommended pattern:

- Keep deterministic policy as the enforcement base.
- Add optional semantic classifiers only where risk justifies the dependency footprint.
- Use guardrail adapters, golden datasets, and runtime evaluation for high-risk workflows.
- Require human review for critical autonomous actions.
- Treat semantic scores as decision evidence, not as the only authority.

## Approval Orchestration Boundary

PolicyAware can return `require_approval` decisions, reason codes, policy IDs, remediation, and audit metadata. That is the governance decision layer.

A full human-in-the-loop workflow also requires durable suspension state, approver identity, secure resume or terminate APIs, timeout behavior, escalation rules, and integrations with Slack, PagerDuty, ServiceNow, Jira, or internal workflow systems.

Recommended pattern:

- Store approval requests in a durable application or workflow store.
- Include trace ID, policy ID, reason code, tenant, role, tool/action, and redacted arguments.
- Resume only after verifying approver identity and authorization.
- Expire or deny stale approval requests.
- Audit the full path from request to approval to resumed or terminated execution.

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
