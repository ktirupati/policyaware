from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from policyaware import (  # noqa: E402
    DataProtectionEngine,
    Gateway,
    GatewayRequest,
    PolicyEngine,
    RiskClassifier,
    ToolCallRequest,
    ToolPolicyEngine,
)


def percentile(values: list[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((percent / 100) * (len(ordered) - 1)))))
    return ordered[index]


def run_benchmark(
    name: str,
    fn: Callable[[], object],
    *,
    requests: int,
    concurrency: int,
) -> dict[str, float | int | str]:
    latencies: list[float] = []

    def timed() -> float:
        started = time.perf_counter_ns()
        fn()
        return (time.perf_counter_ns() - started) / 1_000.0

    started = time.perf_counter()
    if concurrency <= 1:
        for _ in range(requests):
            latencies.append(timed())
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            for latency in pool.map(lambda _: timed(), range(requests)):
                latencies.append(latency)
    total_seconds = time.perf_counter() - started

    return {
        "name": name,
        "requests": requests,
        "concurrency": concurrency,
        "total_ms": round(total_seconds * 1000, 3),
        "requests_per_second": round(requests / total_seconds, 2) if total_seconds else 0.0,
        "median_us": round(statistics.median(latencies), 3),
        "p95_us": round(percentile(latencies, 95), 3),
        "p99_us": round(percentile(latencies, 99), 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark local PolicyAware governance overhead.")
    parser.add_argument("--requests", type=int, default=1000, help="Number of benchmark iterations.")
    parser.add_argument("--concurrency", type=int, default=1, help="Thread concurrency for timed runs.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of a table.")
    args = parser.parse_args()

    policy = PolicyEngine.from_file(ROOT / "examples/policies/basic.yaml")
    tool_policy = ToolPolicyEngine.from_file(ROOT / "examples/policies/tool-governance.yaml")
    gateway = Gateway.from_policy_file(ROOT / "examples/zero-config-openai/policy.yaml")
    gateway.audit_logger.path = ROOT / ".policyaware" / "benchmark-traces.jsonl"
    data = DataProtectionEngine()
    risk_classifier = RiskClassifier()

    request = GatewayRequest(
        tenant="acme",
        app="bench",
        user={"id": "u_1", "role": "support_agent"},
        context={"region": "us", "risk": "low", "task_type": "summarization"},
        messages=[{"role": "user", "content": "Email jane@example.com about this case."}],
    )
    findings = data.inspect(request.prompt_text)
    risk = risk_classifier.classify(request, findings)
    tool_request = ToolCallRequest(
        agent_id="code_assistant",
        connector_id="github",
        action="create_pr",
        user={"role": "developer"},
    )

    benchmarks = [
        ("data_protection.inspect", lambda: data.inspect(request.prompt_text)),
        ("policy_engine.decide", lambda: policy.decide(request, findings, risk)),
        (
            "gateway.inspect_and_mutate",
            lambda: gateway.inspect_and_mutate(
                "Email jane@example.com about claim ACME-42.",
                context={"user_role": "billing_admin", "risk": "low"},
                app="zero-config",
            ),
        ),
        ("tool_policy.decide", lambda: tool_policy.decide(tool_request)),
    ]
    results = [
        run_benchmark(
            name,
            fn,
            requests=args.requests,
            concurrency=max(1, args.concurrency),
        )
        for name, fn in benchmarks
    ]

    if args.json:
        print(json.dumps({"benchmarks": results}, indent=2))
        return

    print("PolicyAware local benchmark results")
    print(f"requests={args.requests} concurrency={max(1, args.concurrency)}")
    print()
    print(
        f"{'name':32} {'median_us':>12} {'p95_us':>12} {'p99_us':>12} "
        f"{'total_ms':>12} {'rps':>12}"
    )
    for result in results:
        print(
            f"{str(result['name']):32} "
            f"{float(result['median_us']):12.3f} "
            f"{float(result['p95_us']):12.3f} "
            f"{float(result['p99_us']):12.3f} "
            f"{float(result['total_ms']):12.3f} "
            f"{float(result['requests_per_second']):12.2f}"
        )


if __name__ == "__main__":
    main()
