# Security Model

PolicyAware is designed around deny-by-default governance, layered checks, explicit tool authorization, and audit-ready decisions.

## Security Boundary

PolicyAware helps protect AI workflows at four layers:

| Layer | What PolicyAware Checks | Timing |
| --- | --- | --- |
| Request input | Prompt text, messages, user role, tenant, region, task type, risk, domain, autonomy, budget, and token context | Before model execution |
| Tool execution | Agent ID, connector name, action name, arguments, role, tenant, approval requirements, and budget/rate metadata | Before tool execution |
| Model output | Sensitive data leakage, citation requirements, policy consistency, and configured output guards | After model output |
| Repository code | PII, PHI, secrets, direct model calls, weak routing, missing tool governance, audit gaps, and configuration risks | Before deployment or during CI |

## Deny-By-Default Policy

PolicyAware policies should default to deny:

```yaml
id: secure_baseline
default: deny

rules:
  - name: block_secrets
    effect: deny
    when:
      data.contains_secrets: true

  - name: allow_low_risk_support
    effect: allow
    when:
      user.role: support_agent
      request.region: us
      request.risk_in: [low, medium]
```

If no allow rule matches, the request is denied. Transform rules, such as redaction, do not grant access by themselves.

## Pre-Execution Enforcement

Use `Gateway.chat(...)`, middleware, or tool governance checks when PolicyAware must decide before execution.

Pre-execution controls include:

- PII, PHI, secrets, and sensitive data detection
- role and tenant checks
- region and compliance checks
- risk-tier classification
- deny, approval, allow, and conditional allow decisions
- redaction before model execution
- model selection constraints
- MCP connector/action permission checks

## Post-Execution Evaluation

Post-execution checks help detect unsafe or noncompliant output.

Examples:

- sensitive data leakage in model response
- missing citations for RAG answers
- policy consistency checks
- configured output guardrail adapters
- runtime evaluation scores for audit traces

Post-execution evaluation should not be the only protection for high-risk workflows. Use pre-execution policy and tool governance first.

## Human Approval

Use approval outcomes for:

- high-risk or critical risk tiers
- regulated-domain workflows
- autonomous or agentic actions
- destructive tool actions
- external writes, deletes, deploys, purchases, payments, or permission changes
- workflows involving PHI, financial data, legal data, or privileged internal data

```yaml
rules:
  - name: require_approval_for_high_risk
    effect: require_approval
    when:
      risk.tier_in: [high, critical]
```

## Tool Governance

MCP-style tools should be governed separately from model prompts.

```yaml
tools:
  rules:
    - name: allow_github_read
      effect: allow
      connector_id: github
      actions: [read_file, list_issues]
      roles: [developer]

    - name: require_approval_for_writes
      effect: require_approval
      connector_id: github
      actions: [create_pr, merge_pr, delete_branch]
      roles: [developer]
```

This keeps agent tool execution explicit and reviewable.

## Static Scan Boundary

`policyaware scan` is a pre-deployment static analysis tool. It does not execute code, call providers, or load ML models.

It can find likely governance risks, but it does not prove runtime exploitability. Treat scan findings as review signals for engineering, security, and compliance teams.

## Layered Security Recommendation

For production workloads, combine:

1. `policyaware scan` in CI.
2. YAML policy validation.
3. `Gateway.chat(...)` or middleware for enforceable request controls.
4. `ToolPolicyEngine` before any MCP/tool call.
5. Runtime evaluation for output leakage and citations.
6. Audit traces and evidence exports.
7. Human approval for high-risk and regulated actions.
