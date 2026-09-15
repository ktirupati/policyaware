# PolicyAware 0.4.5 Release Notes

PolicyAware `0.4.5` focuses on developer trust, reproducible onboarding, and production-readiness documentation.

## Highlights

- Added a zero-config OpenAI preflight example with `Gateway.inspect_and_mutate(...)`.
- Added reproducible local benchmark scripts for policy, privacy, gateway preflight, tool decisions, and repository scans.
- Added trust-first documentation that separates stable core features from optional adapters and roadmap-oriented capabilities.
- Added cross-platform universal wheel verification and a corrected PyPI publishing workflow for the current pure-Python package.
- Added GitHub Pages deployment workflow for the static docs site.
- Added RAG retrieval-governance documentation for indirect prompt-injection defense.
- Added dashboard and deterministic policy test-harness documentation and commands.

## Install

```bash
pip install --upgrade policyaware
```

## Quick Verification

```bash
policyaware about
policyaware init --out policyaware.yaml --force
policyaware policy validate policyaware.yaml
policyaware scan . --format html,json
```

## New Raw-Client Preflight Pattern

```python
import policyaware
from openai import OpenAI

gateway = policyaware.Gateway.from_policy_file("policy.yaml")
client = OpenAI()
safe_prompt, metadata = gateway.inspect_and_mutate(
    prompt="Email jane@example.com about claim ACME-42.",
    context={"user_role": "billing_admin", "risk": "low"},
    app="zero-config",
)
response = client.responses.create(model="gpt-4.1-mini", input=safe_prompt)
```

Denied or approval-required requests fail closed with `PermissionError`.

## Benchmark Commands

```bash
python benchmarks/benchmark_policy_engine.py --requests 1000 --concurrency 1
python benchmarks/benchmark_policy_engine.py --requests 1000 --concurrency 20
python benchmarks/benchmark_scan.py . --iterations 3
```

Benchmark results depend on hardware, Python version, policy shape, enabled extras, and audit configuration. Treat repository samples as guidance, not a performance guarantee.

## Best Next Demo

The strongest differentiator to show publicly is MCP governance:

```bash
python examples/mcp-policy-proxy-demo/mcp_proxy_demo.py
```

It demonstrates a raw MCP JSON-RPC `tools/call` request being allowed, approval-gated, denied, or sanitized before the MCP server touches local infrastructure.

