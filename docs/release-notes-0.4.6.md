# PolicyAware 0.4.6 Release Notes

PolicyAware `0.4.6` focuses on lightweight developer ergonomics for AI policy-as-code workflows.

## Highlights

- Added starter policy profiles for `mcp`, `rag`, `pii`, and `agent`.
- Added `policyaware policy summarize` for reviewer-friendly policy summaries.
- Added `policyaware policy lint` for policy design warnings beyond schema validation.
- Added `policyaware policy diff` for GitOps review of YAML policy changes.
- Added `policyaware protect inspect` for quick sensitive-data category checks without redaction.
- Added `policyaware protect redact` for deterministic redaction previews.
- Added `policyaware examples copy` for copying runnable examples into a local workspace.

## Install

```bash
pip install --upgrade policyaware
```

## Quick Verification

```bash
policyaware init --profile mcp --out mcp-policy.yaml
policyaware policy validate mcp-policy.yaml
policyaware policy summarize mcp-policy.yaml
policyaware policy lint mcp-policy.yaml
policyaware protect inspect "Email jane@example.com" --json
policyaware protect redact "Email jane@example.com"
policyaware examples copy mcp-policy-proxy-demo ./policyaware-mcp-demo
```

## Why This Release Matters

These commands make PolicyAware easier to adopt in local development and CI without adding heavy dependencies. Teams can generate focused policies, inspect data protection behavior, review YAML policy changes, and copy runnable examples with simple CLI commands.
