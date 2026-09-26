# PolicyAware Quickstart

Use this path to verify PolicyAware locally in about 30 seconds.

## Install

```bash
pip install policyaware
```

Check the installed version:

```bash
policyaware --version
```

## Run The Zero-Config Demo

```bash
policyaware quickstart
```

This creates `.policyaware/demo/policyaware.demo.yaml` and runs the real policy doctor report. The demo policy is deny-by-default and includes PII redaction, secret denial, MCP/tool approval gating, token-budget control, role constraints, and risk constraints.

`policyaware quickstart` is the friendly alias for `policyaware demo doctor`; both commands run the same zero-config local demo.

For machine-readable output:

```bash
policyaware quickstart --json
```

## Scan A Repository

From the root of an AI, LLM, RAG, MCP, or agent repository:

```bash
policyaware scan .
```

For CI-friendly outputs:

```bash
policyaware scan . --format html,json,sarif,markdown --fail-on high
```

## Create Your Own Policy

```bash
policyaware init --profile mcp --out policyaware.yaml
policyaware policy validate policyaware.yaml --json
policyaware policy doctor policyaware.yaml
policyaware policy checklist policyaware.yaml
policyaware policy normalize policyaware.yaml --out policyaware.normalized.yaml
```

## Next Steps

- Read the [CLI usability guide](cli-usability.md).
- Review the [local code scan guide](local-code-scan.md).
- Try the [MCP policy proxy](mcp-policy-proxy.md).
- Use the [GitHub Action](github-action.md) for pull-request checks.
