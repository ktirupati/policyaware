# PolicyAware Working Examples

This guide shows working examples for the current PolicyAware AI Gateway MVP.

PolicyAware is a Python framework for governed AI execution. It checks AI requests before they reach models or tools, applies policies, classifies risk, explains decisions, evaluates outputs, and writes audit traces.

## 1. Install

Install the published package:

```bash
pip install policyaware
```

For local development from a cloned repository:

```bash
pip install -e ".[dev]"
```

## 2. Run A Local Simulation

```bash
policyaware dev simulate
```

This runs several built-in scenarios:

- Low-risk allowed request
- PII redaction request
- High-risk approval request
- Unknown-role denial request

Expected behavior:

- Normal support requests are allowed.
- Prompts with PII are conditionally allowed with redaction.
- High-risk requests require approval.
- Unknown roles are denied by default.

## 3. Send A Prompt Through The Gateway

```bash
policyaware chat examples/policies/basic.yaml "Summarize this customer ticket." --role support_agent --risk low
```

The gateway will:

1. Inspect the prompt for sensitive data.
2. Classify request risk.
3. Apply `examples/policies/basic.yaml`.
4. Route to the simulated local provider.
5. Evaluate the output.
6. Write an audit trace to `.policyaware/traces.jsonl`.

Example response fields:

```json
{
  "policy": {
    "decision": "allow",
    "risk_tier": "low",
    "reason_codes": ["RISK.LOW", "POLICY.ALLOW_MATCHED"]
  },
  "route": {
    "model": {
      "name": "local/sim-small"
    }
  }
}
```

## 4. Test A Policy Decision

```bash
policyaware policy test examples/policies/basic.yaml \
  --role support_agent \
  --risk low \
  --prompt "Summarize this customer request."
```

This prints a table with:

- Decision
- Risk tier
- Human-readable reason
- Reason codes
- Matched policy rules
- Actions
- Trace ID

## 5. Explain A Policy Decision

```bash
policyaware policy explain examples/policies/basic.yaml \
  --role support_agent \
  --prompt "Email jane@example.com about the claim."
```

Expected behavior:

- The email is detected as PII.
- The request is allowed only with redaction.
- The decision includes reason codes and remediation.

Example explanation shape:

```json
{
  "decision": "conditional_allow",
  "summary": "conditional_allow: Allowed with transforms.",
  "reason_codes": [
    "DATA.PII_DETECTED",
    "RISK.MEDIUM",
    "POLICY.ALLOW_MATCHED",
    "POLICY.TRANSFORM_APPLIED"
  ],
  "matched_policy_ids": [
    "allow_low_medium_risk_enterprise_users",
    "redact_pii_for_non_privileged_users"
  ],
  "violated_policy_ids": [],
  "remediation": [
    "Transforms were applied before execution."
  ]
}
```

## 6. Deny Secrets Before Model Execution

```bash
policyaware policy explain examples/policies/basic.yaml \
  --role developer \
  --prompt "Use secret_api_key_abcdefghijklmnop in the deployment."
```

Expected behavior:

- Secret-like content is detected.
- Policy rule `block_secrets` matches.
- The request is denied before model execution.

Expected reason codes include:

```text
DATA.SECRET_DETECTED
POLICY.DENY_MATCHED
```

## 7. Classify Request Risk

```bash
policyaware risk classify "Review patient id ABCDE diagnosis: flu" \
  --role analyst \
  --domain healthcare \
  --autonomy agentic \
  --action-type read
```

Expected behavior:

- Healthcare domain increases risk.
- Diagnosis text is treated as PHI-like content.
- Agentic/autonomous context increases risk.

Example output shape:

```json
{
  "tier": "high",
  "score": 0.75,
  "factors": [
    "phi",
    "regulated_domain:healthcare",
    "autonomy:agentic"
  ],
  "reason_codes": [
    "DATA.PHI_DETECTED",
    "RISK.REGULATED_DOMAIN",
    "RISK.HIGH_AUTONOMY",
    "RISK.HIGH"
  ],
  "fail_safe": "deny"
}
```

## 8. Use The Python SDK

```python
from policyaware import Gateway, GatewayRequest

gateway = Gateway.from_policy_file("examples/policies/basic.yaml")

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="support-copilot",
        user={"id": "u_123", "role": "support_agent"},
        context={
            "region": "us",
            "task_type": "support",
            "risk": "low",
            "domain": "support",
        },
        messages=[
            {"role": "user", "content": "Email jane@example.com about the claim."}
        ],
    )
)

print(response.content)
print(response.policy.decision)
print(response.policy.risk_tier)
print(response.policy.reason_codes)
print(response.policy.explanation.summary)
print(response.trace_id)
```

What happens:

- `jane@example.com` is detected as PII.
- Policy allows the request for `support_agent`.
- Policy applies a `redact` transform.
- The simulated provider receives redacted text.
- The response includes a trace ID.

## 9. Govern MCP-Style Tool Access

Use the sample tool policy:

```bash
policyaware tools check examples/policies/tool-governance.yaml \
  --agent code_assistant \
  --connector github \
  --action read_file \
  --role developer
```

Expected decision:

```json
{
  "decision": "allow",
  "connector_id": "github",
  "action": "read_file",
  "reason_codes": ["TOOL.RATE_LIMIT_DECLARED", "TOOL.ALLOWED"]
}
```

Check a write action:

```bash
policyaware tools check examples/policies/tool-governance.yaml \
  --agent code_assistant \
  --connector github \
  --action create_pr \
  --role developer
```

Expected decision:

```json
{
  "decision": "require_approval",
  "connector_id": "github",
  "action": "create_pr",
  "approval_required": true,
  "reason_codes": ["TOOL.APPROVAL_REQUIRED"]
}
```

Check a destructive action:

```bash
policyaware tools check examples/policies/tool-governance.yaml \
  --agent code_assistant \
  --connector github \
  --action delete_branch \
  --role developer
```

Expected decision:

```json
{
  "decision": "deny",
  "connector_id": "github",
  "action": "delete_branch",
  "reason_codes": ["TOOL.DENIED"]
}
```

## 10. Parse A Governance Eval Suite

```bash
policyaware eval run examples/evals/governance_cases.yaml
```

The current MVP parses governance eval definitions and returns a report-shaped object.

Example output shape:

```json
{
  "suite": "governance_policy_eval",
  "checks": 4,
  "cases": 2,
  "status": "configured",
  "report": {
    "policy_compliance_score": 1.0,
    "safety_score": 1.0
  }
}
```

The next production step is to execute these cases against real model providers and compare actual policy outcomes with expected outcomes.

## 11. Create An Audit Trace

Run a request:

```bash
policyaware chat examples/policies/basic.yaml "Summarize this customer ticket." --role support_agent --risk low
```

The response includes a `trace_id`, and the framework writes a trace to:

```text
.policyaware/traces.jsonl
```

Audit traces include:

- Request ID
- Tenant
- App
- User ID
- Task type
- Policy decision
- Matched policy rules
- Reason codes
- Risk tier
- Model route
- Token estimates
- Cost estimate
- Latency
- Eval scores
- Request snapshot
- Response snapshot

## 12. Generate An Audit Bundle

Use the trace ID from a previous run:

```bash
policyaware audit bundle trc_your_trace_id \
  --traces-file .policyaware/traces.jsonl \
  --out .policyaware/audit-bundle
```

Generated files:

```text
.policyaware/audit-bundle/
  trace.json
  decision.json
  request.json
  eval_report.json
  summary.md
```

This bundle is meant for security, compliance, or incident review.

## 13. Replay A Trace Against A Policy

```bash
policyaware audit replay trc_your_trace_id \
  examples/policies/basic.yaml \
  --traces-file .policyaware/traces.jsonl
```

The replay command:

1. Loads the stored request snapshot.
2. Runs it through the current policy.
3. Compares the original decision with the replay decision.

Example output shape:

```json
{
  "trace_id": "trc_123",
  "original_decision": "allow",
  "replay_decision": "allow",
  "replay_reason_codes": ["RISK.LOW", "POLICY.ALLOW_MATCHED"],
  "changed": false
}
```

## 14. Example Policy: Basic Enterprise Policy

File:

```text
examples/policies/basic.yaml
```

This policy demonstrates:

- Critical risk approval
- Secret blocking
- Low/medium risk allow rules
- PII redaction for non-privileged users
- High/critical risk approval

```yaml
id: basic_enterprise_policy
default: deny

rules:
  - name: critical_requires_approval
    effect: require_approval
    when:
      risk.tier: "critical"

  - name: block_secrets
    effect: deny
    when:
      data.contains_secrets: true

  - name: allow_low_medium_risk_enterprise_users
    effect: allow
    when:
      user.role_in: ["support_agent", "claims_adjuster", "developer", "privacy_admin"]
      request.risk_in: ["low", "medium"]
      request.region: "us"

  - name: redact_pii_for_non_privileged_users
    effect: transform
    action: redact
    when:
      data.contains_pii: true
      user.role_not_in: ["privacy_admin", "compliance_officer"]

  - name: require_approval_for_high_risk
    effect: require_approval
    when:
      risk.tier_in: ["high", "critical"]
```

## 15. Example Tool Governance Policy

File:

```text
examples/policies/tool-governance.yaml
```

This policy demonstrates:

- GitHub read access for developers
- GitHub PR creation requiring approval
- GitHub branch deletion denied
- Snowflake query permission with argument restrictions

```yaml
id: mcp_tool_governance
schema_version: "0.2"
default: deny

connectors:
  - id: github
    type: mcp
    risk: medium
    actions:
      read_file:
        effect: allow
        risk: low
        side_effect: none
        when:
          user.role_in: ["developer", "security_engineer"]
        limits:
          calls_per_minute: 60

      create_pr:
        effect: require_approval
        risk: high
        side_effect: write
        when:
          user.role_in: ["developer", "maintainer"]

      delete_branch:
        effect: deny
        risk: critical
        side_effect: delete
```

## 16. What Is Simulated In The MVP

The current provider is intentionally simulated:

```text
local/sim-small
```

That means examples work without external API keys.

Production adapters can later be added for:

- OpenAI-compatible APIs
- Azure OpenAI
- Anthropic
- Bedrock
- Vertex AI
- Cohere
- Mistral
- vLLM
- Ollama
- TGI

## 17. Full-Stack Guardrails Example

PolicyAware can orchestrate optional NeMo Guardrails, Guardrails AI, or custom guard validators while keeping policy, routing, audit, and evaluation centralized.

Runnable local demo without external dependencies:

```bash
cd examples/full-stack-guardrails
python demo.py
```

Optional integrations:

```bash
pip install "policyaware[nemo]"
pip install "policyaware[guardrails-ai]"
pip install "policyaware[full]"
```

Python shape:

```python
from policyaware import Gateway, GuardrailsAIAdapter, NeMoGuardrailsAdapter

gateway = Gateway.from_policy_file("policy.yaml")
gateway.add_input_guard(NeMoGuardrailsAdapter(config_path="rails/"))
gateway.add_output_guard(GuardrailsAIAdapter(rail_spec="guardrails/spec.rail"))
```

Guard results are included in:

```python
response.metadata["guardrails"]
```

## 18. What This Framework Is Best For

PolicyAware is useful when you need to govern:

- Enterprise copilots
- RAG assistants
- Customer support AI
- Code assistants
- Analytics agents
- Healthcare, finance, HR, legal, or insurance workflows
- AI agents with tool access
- MCP-style connector access

## 19. Current MVP Limitations

The current framework is a strong MVP, but these pieces are still future production work:

- Real provider adapters
- Full MCP proxy execution
- Persistent rate-limit enforcement
- Persistent audit backend
- OpenTelemetry and Prometheus exporters
- Full golden dataset execution
- Approval workflow integrations
- Dashboard or local trace viewer

## 20. Fast Smoke Test

Run these after local install:

```bash
policyaware dev simulate
policyaware policy explain examples/policies/basic.yaml --prompt "Email jane@example.com"
policyaware risk classify "Review patient id ABCDE diagnosis: flu" --domain healthcare --autonomy agentic
policyaware tools check examples/policies/tool-governance.yaml --agent code_assistant --connector github --action create_pr
policyaware eval run examples/evals/governance_cases.yaml
```

If those commands run, the core MVP is wired correctly.

## 21. Share Feedback

If an example helps you build or evaluate a real AI governance workflow, please share feedback:

- Private structured feedback form: https://docs.google.com/forms/d/e/1FAIpQLSc2QcQydjXZ0YF9bbVSpudoM5y8noxIP5jU-acVmjlyvf6Slg/viewform
- GitHub Discussions: https://github.com/ktirupati/policyaware/discussions
- Testimonials and Show and Tell: https://github.com/ktirupati/policyaware/discussions/categories/show-and-tell

Please do not share secrets, private prompts, PHI, PII, customer data, or confidential internal details.
