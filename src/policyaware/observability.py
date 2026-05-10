from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class PrometheusExporter:
    def export(self, traces: list[dict[str, Any]]) -> str:
        total = len(traces)
        decisions: dict[str, int] = {}
        risk: dict[str, int] = {}
        latency_values = [int(trace.get("latency_ms") or 0) for trace in traces]
        for trace in traces:
            decisions[trace.get("policy_decision", "unknown")] = (
                decisions.get(trace.get("policy_decision", "unknown"), 0) + 1
            )
            risk[trace.get("risk_tier", "unknown")] = risk.get(trace.get("risk_tier", "unknown"), 0) + 1

        lines = [
            "# HELP policyaware_requests_total Total governed AI requests.",
            "# TYPE policyaware_requests_total counter",
            f"policyaware_requests_total {total}",
            "# HELP policyaware_policy_decisions_total Policy decisions by outcome.",
            "# TYPE policyaware_policy_decisions_total counter",
        ]
        for decision, count in sorted(decisions.items()):
            lines.append(f'policyaware_policy_decisions_total{{decision="{decision}"}} {count}')
        lines.extend(
            [
                "# HELP policyaware_risk_tiers_total Requests by risk tier.",
                "# TYPE policyaware_risk_tiers_total counter",
            ]
        )
        for tier, count in sorted(risk.items()):
            lines.append(f'policyaware_risk_tiers_total{{tier="{tier}"}} {count}')
        if latency_values:
            lines.extend(
                [
                    "# HELP policyaware_latency_ms_sum Sum of request latency in milliseconds.",
                    "# TYPE policyaware_latency_ms_sum counter",
                    f"policyaware_latency_ms_sum {sum(latency_values)}",
                ]
            )
        return "\n".join(lines) + "\n"

    def write(self, traces: list[dict[str, Any]], path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.export(traces), encoding="utf-8")
        return output


class OpenTelemetryJsonExporter:
    def export(self, traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        spans: list[dict[str, Any]] = []
        for trace in traces:
            spans.append(
                {
                    "name": "policyaware.gateway.request",
                    "trace_id": trace.get("trace_id"),
                    "attributes": {
                        "policyaware.tenant": trace.get("tenant"),
                        "policyaware.app": trace.get("app"),
                        "policyaware.decision": trace.get("policy_decision"),
                        "policyaware.risk_tier": trace.get("risk_tier"),
                        "policyaware.model": trace.get("model"),
                        "policyaware.reason_codes": trace.get("reason_codes", []),
                    },
                    "duration_ms": trace.get("latency_ms"),
                    "created_at": trace.get("created_at"),
                }
            )
        return spans

    def write(self, traces: list[dict[str, Any]], path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(self.export(traces), indent=2), encoding="utf-8")
        return output
