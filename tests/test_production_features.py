from pathlib import Path

from policyaware.audit import SQLiteAuditLogger, TraceViewer
from policyaware.evals import EvalSuiteRunner
from policyaware.gateway import Gateway
from policyaware.models import GatewayRequest
from policyaware.observability import OpenTelemetryJsonExporter, PrometheusExporter
from policyaware.providers import ProviderRegistry, SimulatedProvider


def test_sqlite_audit_logger_and_trace_viewer(tmp_path: Path) -> None:
    gateway = Gateway.from_policy_file("examples/policies/basic.yaml")
    logger = SQLiteAuditLogger(tmp_path / "audit.db")
    gateway.audit_logger = logger

    response = gateway.chat(
        GatewayRequest(
            tenant="acme",
            app="test",
            user={"id": "u1", "role": "support_agent"},
            context={"region": "us", "risk": "low", "task_type": "support"},
            messages=[{"role": "user", "content": "Summarize this ticket."}],
        )
    )

    assert logger.find_trace(response.trace_id) is not None
    viewer = TraceViewer().write_html(logger.read_traces(), tmp_path / "viewer.html")
    assert viewer.exists()


def test_observability_exporters() -> None:
    traces = [
        {
            "trace_id": "trc_1",
            "tenant": "acme",
            "app": "test",
            "policy_decision": "allow",
            "risk_tier": "low",
            "latency_ms": 12,
        }
    ]

    prometheus = PrometheusExporter().export(traces)
    otel = OpenTelemetryJsonExporter().export(traces)

    assert "policyaware_requests_total 1" in prometheus
    assert otel[0]["name"] == "policyaware.gateway.request"


def test_executable_golden_eval() -> None:
    gateway = Gateway.from_policy_file("examples/policies/basic.yaml")

    result = EvalSuiteRunner().run_file(
        "examples/evals/executable_governance_cases.yaml",
        gateway=gateway,
    )

    assert result["report"]["cases"] == 3
    assert result["report"]["failed"] == 0


def test_provider_registry_returns_registered_provider() -> None:
    registry = ProviderRegistry({"local": SimulatedProvider()})
    provider = registry.for_model(Gateway.from_policy_file("examples/policies/basic.yaml").router.models[0])

    assert isinstance(provider, SimulatedProvider)

