# Lightweight Benchmarks

PolicyAware includes benchmark guidance so maintainers and users can measure local governance overhead before production rollout.

These benchmarks are intentionally simple and local. They do not call external model providers.

## Benchmark Targets

| Area | What To Measure | Why It Matters |
| --- | --- | --- |
| Data protection | `DataProtectionEngine.inspect(...)` over representative prompts | Sensitive-data checks should be fast enough for request-time use. |
| Policy decision | `PolicyEngine.decide(...)` over common contexts | Deny-by-default policy should add low overhead. |
| Tool governance | `ToolPolicyEngine.decide(...)` over connector/action calls | Agent tool checks should be cheap enough to run before every tool call. |
| Local scan | `policyaware scan ./repo` | Pre-deployment governance scanning should remain practical for developer and CI usage. |
| Evidence export | `to_agt_*` helpers | Audit/evidence conversion should be cheap enough for request-time evidence capture. |

## Reproducible Benchmark Scripts

The repository includes runnable benchmark scripts in `benchmarks/`.

Policy, privacy, gateway preflight, and tool-governance benchmark:

```bash
python benchmarks/benchmark_policy_engine.py --requests 1000 --concurrency 1
python benchmarks/benchmark_policy_engine.py --requests 1000 --concurrency 20
```

JSON output for CI or repeated tracking:

```bash
python benchmarks/benchmark_policy_engine.py --requests 1000 --concurrency 20 --json
```

Local scan benchmark:

```bash
python benchmarks/benchmark_scan.py . --iterations 3
python benchmarks/benchmark_scan.py examples --iterations 5 --json
```

The policy benchmark reports:

- median latency in microseconds
- p95 latency in microseconds
- p99 latency in microseconds
- total runtime
- requests per second

## Scan Timing

```bash
policyaware scan ./my-ai-app --format html,json
```

The terminal dashboard reports total scan time, files scanned, and findings.

## Notes

- Base PolicyAware checks are rules-based and local.
- Optional ML integrations such as Presidio, Transformers, Torch, or ONNX can add model-load time and higher runtime overhead.
- PolicyAware currently ships as a pure-Python package. The wheel pipeline is ready for future optional native accelerators, but public performance claims should be based on measured benchmark results.
- Run benchmarks on representative repositories and prompts before setting CI thresholds.
