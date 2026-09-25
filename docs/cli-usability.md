# CLI Usability Commands

PolicyAware includes commands that help developers diagnose their setup, generate starter policies, discover examples, copy examples, inspect/redact sensitive text, summarize policies, lint risky policy design, compare policy files, migrate policy files, and create integration recommendation reports.

## Starter Policy Profiles

Generate a deny-by-default starter policy:

```bash
policyaware init
policyaware init --profile baseline
```

Generate focused lightweight policies:

```bash
policyaware init --profile mcp --out mcp-policy.yaml
policyaware init --profile rag --out rag-policy.yaml
policyaware init --profile pii --out pii-policy.yaml
policyaware init --profile agent --out agent-policy.yaml
```

Validate the generated file:

```bash
policyaware policy validate mcp-policy.yaml
```

Profiles are intentionally lightweight YAML templates. They do not install ML dependencies or call external services.

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

## Deterministic Test Harness

Run seeded high-volume policy checks against a YAML file:

```bash
policyaware test-harness policyaware.yaml --requests 10000 --workers 16 --json
```

Standalone entry point:

```bash
policyaware-test-harness policyaware.yaml --requests 10000 --workers 16 --json
```

Use this in CI to catch YAML regressions, unexpected exceptions, and
thread-safety issues before policy changes reach production.

## Visual Policy Simulator

Launch the interactive local dashboard:

```bash
policyaware dashboard --policy examples/policies/basic.yaml --port 8765
```

Optional FastAPI/Uvicorn mode:

```bash
pip install "policyaware[dashboard]"
policyaware dashboard --policy policyaware.yaml --fastapi
```

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

Run a zero-config policy doctor demo:

```bash
policyaware demo doctor
policyaware demo doctor --json
policyaware demo doctor --out .policyaware/demo/policyaware.demo.yaml --force
```

`demo doctor` writes a tiny deny-by-default policy with PII, secrets, MCP/tool, budget, role, and risk signals, then runs the same `policy doctor` report used for real policies. It is useful for onboarding, screenshots, and quick local verification after `pip install policyaware`.

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

Copy an example into your own workspace:

```bash
policyaware examples copy mcp-policy-proxy-demo ./policyaware-mcp-demo
policyaware examples copy pii-redaction-policy ./pii-redaction-demo
```

Use `--force` only when you intentionally want to replace the destination folder.

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

Preview deterministic placeholder redaction:

```bash
policyaware protect redact "Email jane@example.com or call 212-555-7890"
policyaware protect redact "Email jane@example.com" --json
```

Inspect sensitive-data categories without redacting the text:

```bash
policyaware protect inspect "Email jane@example.com or use token_abcd1234abcd1234"
policyaware protect inspect "Email jane@example.com" --json
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

Summarize a policy for reviewers:

```bash
policyaware policy summarize policyaware.yaml
policyaware policy summarize policyaware.yaml --json
```

Lint risky policy design beyond schema validation:

```bash
policyaware policy lint policyaware.yaml
policyaware policy lint policyaware.yaml --json
policyaware policy lint policyaware.yaml --fail-on high
```

`policy lint` warns about patterns such as `default: allow`, missing explicit secret-deny rules, missing PII redaction, missing approval gates, missing budget controls, and broad allow rules.

Run the one-command policy doctor:

```bash
policyaware policy doctor policyaware.yaml
policyaware policy doctor policyaware.yaml --json
policyaware policy doctor policyaware.yaml --fail-on high
```

`policy doctor` rolls validation, summary, lint, and readiness counts into one report. It is the simplest command to use in CI logs, screenshots, and first-time policy reviews.

Run a production-readiness checklist:

```bash
policyaware policy checklist policyaware.yaml
policyaware policy checklist policyaware.yaml --json
policyaware policy checklist policyaware.yaml --fail-on high
```

`policy checklist` is intentionally lightweight. It checks deny-by-default posture, schema validity, explicit rules, secret denial, PII redaction, approval gates, budget controls, MCP/tool coverage, role constraints, and risk constraints. Use it in pull requests when reviewers need a quick readiness signal without installing ML extras.

Normalize YAML key ordering for clean Git diffs:

```bash
policyaware policy normalize policyaware.yaml --out policyaware.normalized.yaml
policyaware policy normalize policyaware.yaml --in-place
```

`policy normalize` preserves rule semantics. It only rewrites YAML ordering so policy-as-code changes are easier to review.

Compare policy changes before review or deployment:

```bash
policyaware policy diff old-policy.yaml new-policy.yaml
policyaware policy diff old-policy.yaml new-policy.yaml --json
policyaware policy diff old-policy.yaml new-policy.yaml --fail-on-relaxed
```

`--fail-on-relaxed` is useful in CI because it exits non-zero when a policy changes from `default: deny` to `default: allow` or removes an explicit deny rule.

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
