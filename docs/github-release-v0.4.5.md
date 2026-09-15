# GitHub Release Draft: PolicyAware 0.4.5

Use this as the GitHub Releases body for tag `v0.4.5`.

## PolicyAware 0.4.5

PolicyAware `0.4.5` focuses on developer trust, reproducible onboarding, and production-readiness documentation.

### Highlights

- Added `Gateway.inspect_and_mutate(...)` for raw-client preflight before prompts leave the application.
- Added `examples/zero-config-openai` with a copy-paste OpenAI preflight example and deny-by-default YAML policy.
- Added reproducible local benchmark scripts in `benchmarks/`.
- Added sample benchmark output with clear machine-specific caveats.
- Added an MCP JSON-RPC policy proxy demo showing allow, redact, approval-required, and deny outcomes.
- Added a production deployment checklist for policy validation, CI scanning, MCP governance, audit traces, fail-closed testing, and benchmarks.
- Added clearer trust-first docs that separate stable core capabilities from optional adapters and future-native-acceleration paths.
- Added GitHub Pages deployment workflow and cross-platform universal wheel verification.
- Added a security issue template for safer vulnerability reporting.

### Install

```bash
pip install --upgrade policyaware
```

### Try The Fastest Examples

```bash
policyaware init --out policyaware.yaml --force
policyaware policy validate policyaware.yaml
policyaware scan . --format html,json
python examples/mcp-policy-proxy-demo/mcp_proxy_demo.py
python benchmarks/benchmark_policy_engine.py --requests 1000 --concurrency 1
```

### Links

- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
- Production checklist: https://github.com/ktirupati/policyaware/blob/main/docs/production-checklist.md
- MCP policy proxy demo: https://github.com/ktirupati/policyaware/tree/main/examples/mcp-policy-proxy-demo
- Benchmarks: https://github.com/ktirupati/policyaware/blob/main/docs/benchmarks.md

### Notes

PolicyAware remains lightweight by default with `pip install policyaware`. Optional stacks such as Presidio, Transformers/Torch, NeMo Guardrails, Guardrails AI, Haystack, and cloud provider helpers should be installed only when the target service needs them.

PolicyAware currently ships as a pure-Python package. The release workflow publishes the universal wheel and source distribution; native Rust/C acceleration should only be claimed after a real native extension exists and benchmark evidence is published.

