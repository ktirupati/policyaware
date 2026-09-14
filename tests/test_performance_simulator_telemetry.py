from __future__ import annotations

from pathlib import Path

from policyaware import (
    FastCoreRuntime,
    OpenTelemetryBridge,
    PolicyAwareTestHarness,
    RuntimeTelemetryCollector,
    VisualPolicySimulator,
    performance_status,
)
from policyaware.dashboard_server import render_dashboard_html, simulate_payload


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


def test_runtime_telemetry_emits_to_native_otel_bridge() -> None:
    class FakeBridge:
        def __init__(self) -> None:
            self.events = []

        def emit_event(self, name, attributes, *, value=1.0):
            self.events.append((name, attributes, value))

    bridge = FakeBridge()
    telemetry = RuntimeTelemetryCollector(otel_bridge=bridge)

    telemetry.record_governance_event(
        event_type="trajectory_mutation",
        tenant="acme",
        app="agent-platform",
        decision="conditional_allow",
    )

    assert bridge.events[0][0] == "policyaware.governance.trajectory_mutation"
    assert bridge.events[0][1]["policyaware.decision"] == "conditional_allow"


def test_opentelemetry_bridge_is_safe_without_sdk() -> None:
    bridge = OpenTelemetryBridge()

    bridge.emit_event("policyaware.test", {"policyaware.blocked": True})
    assert isinstance(bridge.available, bool)


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


def test_interactive_dashboard_renders_policy_playback() -> None:
    result = simulate_payload(
        "examples/policies/basic.yaml",
        prompt="Email jane@example.com about this low risk request.",
        role="support_agent",
        tenant="acme",
        risk="low",
    )
    html = render_dashboard_html(
        policy_file="examples/policies/basic.yaml",
        prompt="Email jane@example.com about this low risk request.",
        result=result,
    )

    assert "PolicyAware Local Policy Simulator" in html
    assert "Policy Playback" in html
    assert result["decision"] in html


def test_policyaware_test_harness_is_deterministic() -> None:
    harness = PolicyAwareTestHarness("examples/policies/basic.yaml", seed=2026)

    first = harness.run(requests=40, workers=4)
    second = harness.run(requests=40, workers=4)

    assert first.errors == 0
    assert second.errors == 0
    assert first.corpus_sha256 == second.corpus_sha256
    assert first.deterministic is True
    assert sum(first.decisions.values()) == 40
