# PolicyAware AI Gateway

PolicyAware AI Gateway is an open-source control plane for governed AI execution across enterprise LLM, RAG, AI agent, and MCP-style tool workflows. It enforces organizational, legal, security, cost, and routing policy before requests reach models or tools, then evaluates outputs for safety, quality, compliance, and auditability.

The default posture is deny-by-default: every request must match an allow or conditional policy before execution.

Documentation site: https://ktirupati.github.io/policyaware/

## What It Provides

- Policy enforcement for RBAC, context, tenant, region, compliance, budgets, tokens, latency, and model constraints.
- PII, PHI, secrets, and sensitive-data detection with redaction actions.
- Multi-provider model routing with fallbacks by policy, task type, risk, cost, availability, and quality.
- Runtime evaluation for safety, policy compliance, grounding, citations, and leakage.
- Risk-tier classification with explainable reason codes.
- MCP/tool governance for connector-level and action-level permissions.
- Full request/response trace, explainable decisions, replay-ready audit logs, and exportable JSONL records.
- Python SDK, CLI, YAML policies, local development mode, and integration shims.

## Quick Start

```bash
pip install policyaware
```

For local development from this repository:

```bash
pip install -e ".[dev]"
policyaware policy test examples/policies/basic.yaml
policyaware policy validate examples/policies/basic.yaml
policyaware policy explain examples/policies/basic.yaml --prompt "Email jane@example.com"
policyaware risk classify "Summarize this patient diagnosis" --domain healthcare
policyaware tools check examples/policies/tool-governance.yaml --agent code_assistant --connector github --action create_pr
policyaware eval run examples/evals/support_rag.yaml
```

For copy-pasteable end-to-end examples, see [Working Examples](docs/working-examples.md).

```python
from policyaware import Gateway, GatewayRequest

gateway = Gateway.from_policy_file("examples/policies/basic.yaml")

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="claims-assistant",
        user={"id": "u_123", "role": "claims_adjuster"},
        context={"region": "us", "task_type": "summarization", "risk": "low"},
        messages=[{"role": "user", "content": "Summarize claim ACME-42."}],
    )
)

print(response.content)
print(response.policy.decision)
print(response.policy.reason_codes)
print(response.trace_id)
```

## Architecture

```text
Application / Agent / RAG App
        |
        v
PolicyAware SDK / Middleware
        |
        v
Identity + Context Resolver
        |
        v
Policy Decision Engine -> Data Protection Engine -> Model Router -> Provider/Tool
        |
        v
Runtime Evaluation -> Audit Trace -> Response
```

## Repository Layout

```text
src/policyaware/
  audit.py              Request traces and audit export records
  cli.py                policyaware CLI
  data_protection.py    PII/PHI/secret detection and redaction
  evals.py              Offline and runtime evaluation primitives
  gateway.py            Main SDK facade
  models.py             Core typed contracts
  policy.py             Deny-by-default policy engine
  providers.py          Provider abstraction and local simulated provider
  routing.py            Policy-aware model routing
  integrations/         FastAPI, Flask, LangChain, LlamaIndex shims
examples/
  policies/
  evals/
tests/
```

## Policy Example

```yaml
id: basic_enterprise_policy
default: deny

rules:
  - name: allow_low_risk_support
    effect: allow
    when:
      user.role_in: ["support_agent", "claims_adjuster"]
      request.risk_in: ["low", "medium"]
      data.contains_secrets: false

  - name: redact_pii_for_non_privileged_users
    effect: transform
    action: redact
    when:
      data.contains_pii: true
      user.role_not_in: ["privacy_admin", "compliance_officer"]

  - name: require_approval_for_high_risk
    effect: require_approval
    when:
      request.risk: "high"
```

## Development Status

This is a production-grade starter framework: the core extension points and executable behavior are present, while provider integrations, enterprise identity adapters, dashboard UI, and long-term storage can be expanded by contributors.

## v0.2 MVP Capabilities

- Deterministic risk classification: low, medium, high, critical.
- Explainable policy decisions with reason codes and remediation.
- Replayable audit trace snapshots.
- Audit bundle generation.
- Tool governance policies for MCP-style connectors and actions.
- Governance-aware eval report schema.
- Provider adapters for OpenAI-compatible APIs, Azure OpenAI, Anthropic, Bedrock, Vertex AI, Ollama, and vLLM.
- SQLite audit storage and static trace viewer.
- Prometheus text and OpenTelemetry-shaped JSON exporters.
- File and webhook approval hooks.
- Executable golden dataset policy checks.

## License

Apache-2.0
