# CLI Usability Commands

PolicyAware includes commands that help developers diagnose their setup, discover examples, run examples, migrate policy files, and create integration recommendation reports.

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
