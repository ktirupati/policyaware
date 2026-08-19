from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any


def _label_value(value: Any) -> str:
    return str(value if value is not None else "unknown").replace("\\", "\\\\").replace('"', '\\"')


def _labels(labels: dict[str, Any]) -> str:
    if not labels:
        return ""
    rendered = ",".join(f'{key}="{_label_value(value)}"' for key, value in sorted(labels.items()))
    return f"{{{rendered}}}"


@dataclass
class TelemetryEvent:
    name: str
    attributes: dict[str, Any] = field(default_factory=dict)
    value: float = 1.0


class RuntimeTelemetryCollector:
    """Dependency-free runtime telemetry for PolicyAware enforcement events.

    The collector is intentionally small and embeddable. It gives applications
    and the sidecar a native metrics surface without forcing a particular SaaS,
    agent, dashboard, or OpenTelemetry SDK dependency into the base package.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._latency_sum_ms = 0.0
        self._latency_count = 0
        self._events: list[TelemetryEvent] = []

    def record_trace(self, trace: dict[str, Any]) -> None:
        labels = {
            "tenant": trace.get("tenant"),
            "app": trace.get("app"),
            "decision": trace.get("policy_decision"),
            "risk_tier": trace.get("risk_tier"),
        }
        model = trace.get("model")
        decision = str(trace.get("policy_decision") or "unknown")
        blocked = decision in {"deny", "require_approval"}
        with self._lock:
            self._inc_locked("policyaware_requests_total", {})
            self._inc_locked("policyaware_requests_total", labels)
            self._inc_locked("policyaware_policy_decisions_total", {"decision": decision})
            self._inc_locked("policyaware_policy_decisions_total", labels)
            self._inc_locked("policyaware_risk_tiers_total", {"tier": trace.get("risk_tier")})
            if decision == "deny":
                self._inc_locked("policyaware_policy_denied_total", {})
                self._inc_locked("policyaware_policy_denied_total", labels)
            if decision == "require_approval":
                self._inc_locked("policyaware_approval_required_total", {})
                self._inc_locked("policyaware_approval_required_total", labels)
            if "redact" in (trace.get("actions") or []):
                self._inc_locked("policyaware_redactions_total", {})
                self._inc_locked("policyaware_redactions_total", labels)
            if model:
                self._inc_locked(
                    "policyaware_model_route_total",
                    {"tenant": trace.get("tenant"), "app": trace.get("app"), "model": model},
                )
            for code in trace.get("reason_codes") or []:
                self._inc_locked(
                    "policyaware_reason_codes_total",
                    {**labels, "reason_code": code},
                )
            for name, score in (trace.get("eval_scores") or {}).items():
                if float(score or 0.0) < 0.5:
                    self._inc_locked(
                        "policyaware_eval_failures_total",
                        {**labels, "eval": name},
                    )
            latency_ms = float(trace.get("latency_ms") or 0.0)
            self._latency_sum_ms += latency_ms
            self._latency_count += 1
            self._events.append(
                TelemetryEvent(
                    name="policyaware.gateway.request",
                    attributes={
                        "policyaware.trace_id": trace.get("trace_id"),
                        "policyaware.tenant": trace.get("tenant"),
                        "policyaware.app": trace.get("app"),
                        "policyaware.decision": trace.get("policy_decision"),
                        "policyaware.blocked": blocked,
                        "policyaware.risk_tier": trace.get("risk_tier"),
                        "policyaware.model": trace.get("model"),
                        "policyaware.reason_codes": trace.get("reason_codes", []),
                        "policyaware.matched_rules": trace.get("matched_rules", []),
                    },
                    value=latency_ms,
                )
            )

    def record_tool_decision(
        self,
        *,
        tenant: str,
        app: str,
        connector_id: str,
        action: str,
        decision: str,
        approval_required: bool = False,
        reason_codes: list[str] | None = None,
        matched_rules: list[str] | None = None,
    ) -> None:
        labels = {
            "tenant": tenant,
            "app": app,
            "connector_id": connector_id,
            "action": action,
            "decision": decision,
        }
        with self._lock:
            self._inc_locked("policyaware_tool_decisions_total", labels)
            if decision == "deny":
                self._inc_locked("policyaware_tool_denied_total", labels)
            if approval_required:
                self._inc_locked("policyaware_tool_approval_required_total", labels)
            for code in reason_codes or []:
                self._inc_locked(
                    "policyaware_tool_reason_codes_total",
                    {**labels, "reason_code": code},
                )
            self._events.append(
                TelemetryEvent(
                    name="policyaware.tool.decision",
                    attributes={
                        "policyaware.tenant": tenant,
                        "policyaware.app": app,
                        "policyaware.connector_id": connector_id,
                        "policyaware.action": action,
                        "policyaware.decision": decision,
                        "policyaware.blocked": decision == "deny" or approval_required,
                        "policyaware.approval_required": approval_required,
                        "policyaware.reason_codes": reason_codes or [],
                        "policyaware.matched_rules": matched_rules or [],
                    },
                )
            )

    def prometheus_text(self) -> str:
        with self._lock:
            counters = dict(self._counters)
            latency_sum = self._latency_sum_ms
            latency_count = self._latency_count
        lines = [
            "# HELP policyaware_requests_total Total governed AI requests.",
            "# TYPE policyaware_requests_total counter",
            "# HELP policyaware_policy_decisions_total Policy decisions by outcome.",
            "# TYPE policyaware_policy_decisions_total counter",
            "# HELP policyaware_risk_tiers_total Requests by risk tier.",
            "# TYPE policyaware_risk_tiers_total counter",
            "# HELP policyaware_policy_denied_total Requests denied by PolicyAware.",
            "# TYPE policyaware_policy_denied_total counter",
            "# HELP policyaware_approval_required_total Requests requiring human approval.",
            "# TYPE policyaware_approval_required_total counter",
            "# HELP policyaware_redactions_total Requests where redaction was applied.",
            "# TYPE policyaware_redactions_total counter",
            "# HELP policyaware_model_route_total Model route selections.",
            "# TYPE policyaware_model_route_total counter",
            "# HELP policyaware_reason_codes_total Policy reason-code counts.",
            "# TYPE policyaware_reason_codes_total counter",
            "# HELP policyaware_eval_failures_total Runtime evaluation failures.",
            "# TYPE policyaware_eval_failures_total counter",
            "# HELP policyaware_tool_decisions_total Tool decisions by connector and action.",
            "# TYPE policyaware_tool_decisions_total counter",
            "# HELP policyaware_tool_denied_total Tool calls denied by PolicyAware.",
            "# TYPE policyaware_tool_denied_total counter",
            "# HELP policyaware_tool_approval_required_total Tool calls requiring approval.",
            "# TYPE policyaware_tool_approval_required_total counter",
            "# HELP policyaware_tool_reason_codes_total Tool reason-code counts.",
            "# TYPE policyaware_tool_reason_codes_total counter",
        ]
        for (name, label_items), value in sorted(counters.items()):
            lines.append(f"{name}{_labels(dict(label_items))} {value:g}")
        lines.extend(
            [
                "# HELP policyaware_latency_ms_sum Sum of governed request latency in milliseconds.",
                "# TYPE policyaware_latency_ms_sum counter",
                f"policyaware_latency_ms_sum {latency_sum:g}",
                "# HELP policyaware_latency_ms_count Count of governed request latency observations.",
                "# TYPE policyaware_latency_ms_count counter",
                f"policyaware_latency_ms_count {latency_count}",
            ]
        )
        return "\n".join(lines) + "\n"

    def otel_events(self) -> list[dict[str, Any]]:
        with self._lock:
            events = list(self._events)
        return [
            {
                "name": event.name,
                "attributes": event.attributes,
                "value": event.value,
            }
            for event in events
        ]

    def _inc_locked(self, name: str, labels: dict[str, Any], value: float = 1.0) -> None:
        normalized = tuple(sorted((key, _label_value(label_value)) for key, label_value in labels.items()))
        self._counters[(name, normalized)] += value


class PrometheusExporter:
    def export(self, traces: list[dict[str, Any]]) -> str:
        collector = RuntimeTelemetryCollector()
        for trace in traces:
            collector.record_trace(trace)
        return collector.prometheus_text()

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
