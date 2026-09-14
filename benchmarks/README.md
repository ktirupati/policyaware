# PolicyAware Benchmarks

These benchmarks are intentionally local and dependency-light. They do not call model providers, external guardrail services, cloud APIs, or optional ML frameworks.

Use them to measure the overhead of the stable PolicyAware core before enabling heavier optional extras.

## Policy Engine And Gateway Preflight

```bash
python benchmarks/benchmark_policy_engine.py --requests 1000 --concurrency 1
python benchmarks/benchmark_policy_engine.py --requests 1000 --concurrency 20
```

The script reports median, p95, p99, total runtime, and requests per second for:

- `DataProtectionEngine.inspect(...)`
- `PolicyEngine.decide(...)`
- `Gateway.inspect_and_mutate(...)`
- `ToolPolicyEngine.decide(...)`

## Local Scan

```bash
python benchmarks/benchmark_scan.py . --iterations 3
```

The scan benchmark measures local repository scanning without executing project code.

## Notes

- `pip install policyaware` is the lightweight baseline.
- Optional extras such as `policyaware[privacy]`, `policyaware[ml]`, and `policyaware[guardrails]` can add import time, model load time, memory use, and runtime latency.
- PolicyAware currently ships as a pure-Python package. The wheel pipeline is ready for future native accelerators, but benchmark claims should be based on measured results from these scripts.
