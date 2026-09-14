from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from policyaware.scanner import LocalCodeScanner, ScanConfig  # noqa: E402


def percentile(values: list[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((percent / 100) * (len(ordered) - 1)))))
    return ordered[index]


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark PolicyAware local code scanning.")
    parser.add_argument("target", nargs="?", default=".", help="Directory to scan.")
    parser.add_argument("--iterations", type=int, default=3, help="Number of scan iterations.")
    parser.add_argument("--max-file-size-kb", type=int, default=512, help="Maximum scanned file size.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of a summary.")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    config = ScanConfig(max_file_size_bytes=args.max_file_size_kb * 1024)
    scanner = LocalCodeScanner(config=config)
    timings: list[float] = []
    last_report = None

    for _ in range(max(1, args.iterations)):
        started = time.perf_counter()
        last_report = scanner.scan(target)
        timings.append((time.perf_counter() - started) * 1000)

    result = {
        "target": str(target),
        "iterations": max(1, args.iterations),
        "files_scanned": last_report.files_scanned if last_report else 0,
        "findings": len(last_report.findings) if last_report else 0,
        "median_ms": round(statistics.median(timings), 3),
        "p95_ms": round(percentile(timings, 95), 3),
        "min_ms": round(min(timings), 3),
        "max_ms": round(max(timings), 3),
    }

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print("PolicyAware scan benchmark")
    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
