# CLI Usability Commands

PolicyAware includes commands that help developers diagnose their setup, discover examples, run examples, migrate policy files, and create integration recommendation reports.

## Performance Diagnostics

Check whether PolicyAware is running with the lightweight pure-Python runtime or
a future optional native accelerator:

```bash
policyaware performance status
policyaware performance status --json
```

The base install intentionally stays pure Python. This command gives platform
teams a startup diagnostic they can capture in logs without adding heavy native
dependencies.

## Visual Policy Simulator

Generate a local HTML report explaining one policy decision:

```bash
policyaware dashboard simulate examples/policies/basic.yaml \
  --prompt "Email jane@example.com about this claim" \
  --role support_agent \
  --tenant acme \
  --risk low \
  --out .policyaware/policy-simulator.html
```

Use this when a developer asks why a prompt, action, or agent state was allowed,
denied, redacted, or routed for approval.

## Doctor

Check local installation health:

```bash
policyaware doctor
policyaware doctor --json
policyaware doctor --policy policyaware.yaml
```

`doctor` checks:

- Python version
- required base dependencies
- optional extras presence
- provider environment variable presence without printing secret values
- optional policy YAML validity

Provider checks only report whether environment variables exist. They do not print credential values.

## Examples

List examples:

```bash
policyaware examples list
policyaware examples list --json
```

Run a bundled example from a local repository checkout:

```bash
policyaware examples run langgraph-agent-governance
policyaware examples run enterprise-ai-control-plane
policyaware examples run microsoft-agt-interop
```

The runner only executes known bundled examples.

## Adaptive Governance Helpers

Generate a conservative policy from scan findings:

```bash
policyaware policy suggest . --out policyaware.generated.yaml
policyaware policy validate policyaware.generated.yaml
```

Preflight a proposed multi-step agent plan before real model or tool execution:

```bash
policyaware plan check agent-plan.yaml
policyaware plan check agent-plan.yaml --json
policyaware plan check agent-plan.yaml --fail-on high
```

Replace sensitive values with structurally useful synthetic values:

```bash
policyaware protect synthesize "Email jane@example.com or call 212-555-7890"
policyaware protect synthesize "Email jane@example.com" --json
```

Read more: [Adaptive Governance](adaptive-governance.md).

## Enterprise Structural Layer Helpers

Run a quorum-style jury decision for high-risk agent requests:

```bash
policyaware consensus check "transfer funds for jane@example.com" --risk high --json
```

Sanitize retrieved RAG context before adding it to the model prompt:

```bash
policyaware retrieval sanitize retrieved-context.txt --out retrieved-context.safe.txt
```

Check token, cost, and tool-rate circuit breaker behavior:

```bash
policyaware budget check --session s1 --agent refund-agent --tool payments.refund --cost-usd 10 --max-cost-usd 5
```

Verify a tamper-evident audit chain from local JSONL traces:

```bash
policyaware audit verify-chain .policyaware/traces.jsonl --secret "$POLICYAWARE_AUDIT_SECRET" --out audit-chain.json
```

Read more: [Enterprise Structural Layers](enterprise-structural-layers.md).

## MCP Policy Proxy

Evaluate a raw MCP JSON-RPC `tools/call` request before the MCP server executes it:

```bash
policyaware mcp check examples/policies/tool-governance.yaml mcp-request.json
```

Run a live stdio MCP proxy in front of a real MCP server:

```bash
policyaware mcp proxy examples/policies/tool-governance.yaml \
  --connector filesystem \
  --server-command "python filesystem_mcp_server.py"
```

The proxy can allow and sanitize the forwarded request, deny it with a JSON-RPC error, or return an approval-required error for sensitive actions.

Read more: [MCP Policy Proxy](mcp-policy-proxy.md).

## Edge And Policy Intelligence Helpers

Check air-gapped deployment readiness:

```bash
policyaware airgap check --policy policyaware.yaml --model local --audit-path .policyaware/audit.db
```

Generate framework adapter recipes from one policy:

```bash
policyaware translate policy policyaware.yaml --frameworks langchain,llamaindex,autogen,raw --out policyaware-translations.json
```

Run model drift canaries:

```bash
policyaware drift canary canaries.yaml --threshold 0.1
```

Check decision distribution fairness signals:

```bash
policyaware fairness check decisions.jsonl --attribute group --positive-outcomes approved,selected --threshold 0.2
```

Read more: [Edge And Policy Intelligence](edge-policy-intelligence.md).

## Integration Recommendation HTML

Create a reviewer-friendly HTML report:

```bash
policyaware integrations recommend . --html integration-report.html
```

Add hints:

```bash
policyaware integrations recommend . \
  --use-case agent \
  --framework langgraph \
  --needs "pii audit tools" \
  --html integration-report.html
```

## Policy Migration

Conservatively annotate a policy for a target schema version:

```bash
policyaware policy migrate policyaware.yaml --to 0.3 --out policyaware.v0.3.yaml
policyaware policy validate policyaware.v0.3.yaml
```

The migration helper keeps behavior conservative. It normalizes:

- `schema_version`
- `default`
- `rules`

It does not rewrite rule semantics. Review migrated policies before production use.
