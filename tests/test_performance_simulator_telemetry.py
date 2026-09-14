from __future__ import annotations

from pathlib import Path

from policyaware import (
    FastCoreRuntime,
    RuntimeTelemetryCollector,
    VisualPolicySimulator,
    performance_status,
)


def test_fast_core_runtime_uses_python_fallback() -> None:
    runtime = FastCoreRuntime()

    assert runtime.status.backend in {"python", "native"}
    assert runtime.loads_json('{"ok": true}') == {"ok": True}
    assert runtime.dumps_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'
    assert runtime.find_regex(r"\d+", "id 123 and 456") == ["123", "456"]
    assert performance_status().backend in {"python", "native"}


def test_runtime_telemetry_records_advanced_governance_event() -> None:
    telemetry = RuntimeTelemetryCollector()

    telemetry.record_governance_event(
        event_type="jury veto",
        tenant="acme",
        app="agent-platform",
        decision="deny",
        blocked=True,
        attributes={"policyaware.jury.quorum": "2/3"},
    )

    metrics = telemetry.prometheus_text()
    events = telemetry.otel_events()
    assert "policyaware_governance_events_total" in metrics
    assert "policyaware_governance_blocked_total" in metrics
    assert 'event_type="jury_veto"' in metrics
    assert events[0]["name"] == "policyaware.governance.jury_veto"
    assert events[0]["attributes"]["policyaware.jury.quorum"] == "2/3"


def test_visual_policy_simulator_writes_html(tmp_path: Path) -> None:
    out = tmp_path / "simulator.html"
    simulator = VisualPolicySimulator()
    response = simulator.simulate(
        "examples/policies/basic.yaml",
        prompt="Email jane@example.com about this low risk request.",
        role="support_agent",
        tenant="acme",
    )

    written = simulator.write_html(
        response,
        out,
        prompt="Email jane@example.com about this low risk request.",
        policy_file="examples/policies/basic.yaml",
    )

    html = written.read_text(encoding="utf-8")
    assert "PolicyAware Visual Policy Simulator" in html
    assert response.policy.decision.value in html
    assert "jane@example.com" in html
