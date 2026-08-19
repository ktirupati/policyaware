from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from policyaware import Gateway, GatewayRequest, PolicyAwareSidecar, ToolCallRequest
from policyaware.cli import app
from policyaware.policy_pack_registry import copy_policy_pack, list_policy_packs, read_policy_pack
from policyaware.policy_schema import PolicySchemaValidator
from policyaware.rejections import policy_rejection, tool_rejection
from policyaware.tools import ToolPolicyEngine


ROOT = Path(__file__).resolve().parents[1]


def test_bundled_policy_packs_validate() -> None:
    validator = PolicySchemaValidator()

    for pack in list_policy_packs():
        data = yaml.safe_load(read_policy_pack(pack.id))
        validator.validate(data)


def test_policy_pack_copy_cli(tmp_path: Path) -> None:
    out = tmp_path / "policyaware.yaml"
    result = CliRunner().invoke(app, ["policy", "packs", "copy", "healthcare-hipaa", "--out", str(out)])
    validate = CliRunner().invoke(app, ["policy", "validate", str(out)])

    assert result.exit_code == 0
    assert out.exists()
    assert validate.exit_code == 0


def test_policy_pack_copy_api(tmp_path: Path) -> None:
    out = copy_policy_pack("soc2-ai-controls", tmp_path / "soc2.yaml")

    assert out.exists()
    assert "soc2_ai_controls" in out.read_text(encoding="utf-8")


def test_policy_packs_list_cli_json() -> None:
    result = CliRunner().invoke(app, ["policy", "packs", "list", "--json"])

    assert result.exit_code == 0
    assert "healthcare-hipaa" in result.output
    assert "eu-ai-act-high-risk" in result.output


def test_sidecar_check_endpoint() -> None:
    sidecar = PolicyAwareSidecar(Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml"))

    status, payload = sidecar.handle(
        "POST",
        "/v1/check",
        {
            "tenant": "acme",
            "app": "sidecar-test",
            "user": {"role": "support_agent"},
            "context": {"region": "us", "risk": "low", "task_type": "support"},
            "prompt": "Summarize this ticket.",
        },
    )

    assert status == 200
    assert payload["decision"] in {"allow", "conditional_allow"}
    assert "trace_id" in payload


def test_sidecar_check_endpoint_returns_structured_rejection() -> None:
    gateway = Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml")
    sidecar = PolicyAwareSidecar(gateway)

    status, payload = sidecar.handle(
        "POST",
        "/v1/check",
        {
            "tenant": "acme",
            "app": "sidecar-test",
            "user": {"role": "support_agent"},
            "context": {"region": "us", "risk": "low", "task_type": "support"},
            "prompt": "Use this API key: secret_api_key_abcdefghijklmnop",
        },
    )

    assert status == 200
    assert payload["allowed"] is False
    assert payload["decision"] == "deny"
    assert payload["rejection"]["blocked"] is True
    assert payload["rejection"]["status_code"] == 403
    assert payload["rejection"]["matched_rules"] == ["block_secrets"]
    assert payload["rejection"]["trace_id"] == payload["trace_id"]

    events = gateway.telemetry.otel_events()
    assert events[-1]["attributes"]["policyaware.blocked"] is True
    assert events[-1]["attributes"]["policyaware.matched_rules"] == ["block_secrets"]


def test_sidecar_tool_check_endpoint() -> None:
    sidecar = PolicyAwareSidecar(
        Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml"),
        ToolPolicyEngine.from_file(ROOT / "examples" / "policies" / "tool-governance.yaml"),
    )

    status, payload = sidecar.handle(
        "POST",
        "/v1/tool/check",
        {
            "agent_id": "code_assistant",
            "connector_id": "github",
            "action": "create_pr",
            "user": {"role": "developer"},
        },
    )

    assert status == 200
    assert payload["decision"] == "require_approval"
    assert payload["approval_required"] is True
    assert payload["rejection"]["blocked"] is True
    assert payload["rejection"]["status_code"] == 202
    assert payload["rejection"]["connector_id"] == "github"
    assert payload["rejection"]["action"] == "create_pr"

    metrics_status, metrics = sidecar.handle("GET", "/metrics")

    assert metrics_status == 200
    assert isinstance(metrics, str)
    assert "policyaware_tool_decisions_total" in metrics
    assert "policyaware_tool_approval_required_total" in metrics
    assert 'connector_id="github"' in metrics

    events = sidecar.gateway.telemetry.otel_events()
    assert events[-1]["attributes"]["policyaware.blocked"] is True
    assert events[-1]["attributes"]["policyaware.connector_id"] == "github"


def test_rejection_helpers_return_none_for_allowed_actions() -> None:
    gateway = Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml")
    response = gateway.chat(
        GatewayRequest(
            tenant="acme",
            app="rejection-helper-test",
            user={"role": "support_agent"},
            context={"region": "us", "risk": "low", "task_type": "support"},
            messages=[{"role": "user", "content": "Summarize this public ticket."}],
        )
    )
    tool_decision = ToolPolicyEngine.from_file(
        ROOT / "examples" / "policies" / "tool-governance.yaml"
    ).decide(
        ToolCallRequest(
            agent_id="code_assistant",
            connector_id="github",
            action="read_file",
            user={"role": "developer"},
        )
    )

    assert policy_rejection(response) is None
    assert tool_rejection(tool_decision) is None


def test_sidecar_route_and_evaluate_endpoints() -> None:
    sidecar = PolicyAwareSidecar(Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml"))
    body = {
        "tenant": "acme",
        "app": "sidecar-test",
        "user": {"role": "support_agent"},
        "context": {"region": "us", "risk": "low", "task_type": "support"},
        "messages": [{"role": "user", "content": "Summarize this ticket."}],
    }

    route_status, route_payload = sidecar.handle("POST", "/v1/route", body)
    eval_status, eval_payload = sidecar.handle("POST", "/v1/evaluate", {**body, "output": "Safe answer."})

    assert route_status == 200
    assert route_payload["model"]["name"] == "local/sim-small"
    assert eval_status == 200
    assert eval_payload["results"][0]["name"] == "sensitive_data_leakage"


def test_sidecar_accepts_gateway_request_model() -> None:
    sidecar = PolicyAwareSidecar(Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml"))
    request = GatewayRequest(
        tenant="acme",
        app="sidecar-test",
        user={"role": "support_agent"},
        context={"region": "us", "risk": "low", "task_type": "support"},
        messages=[{"role": "user", "content": "Summarize this ticket."}],
    )

    status, payload = sidecar.handle("POST", "/v1/check", request.model_dump(mode="json"))

    assert status == 200
    assert payload["allowed"] is True


def test_sidecar_bearer_auth_protects_policy_endpoints() -> None:
    sidecar = PolicyAwareSidecar(
        Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml"),
        auth_token="secret-token",
    )

    health_status, _ = sidecar.handle("GET", "/health")
    metrics_missing_status, metrics_missing_payload = sidecar.handle("GET", "/metrics")
    missing_status, missing_payload = sidecar.handle("POST", "/v1/check", {"prompt": "hello"})
    wrong_status, _ = sidecar.handle(
        "POST",
        "/v1/check",
        {"prompt": "hello"},
        headers={"Authorization": "Bearer wrong"},
    )
    ok_status, ok_payload = sidecar.handle(
        "POST",
        "/v1/check",
        {"prompt": "hello"},
        headers={"Authorization": "Bearer secret-token"},
    )
    metrics_status, metrics_payload = sidecar.handle(
        "GET",
        "/metrics",
        headers={"Authorization": "Bearer secret-token"},
    )

    assert health_status == 200
    assert metrics_missing_status == 401
    assert isinstance(metrics_missing_payload, dict)
    assert missing_status == 401
    assert missing_payload["error"] == "unauthorized"
    assert wrong_status == 401
    assert ok_status == 200
    assert ok_payload["decision"] in {"allow", "conditional_allow"}
    assert metrics_status == 200
    assert isinstance(metrics_payload, str)
    assert "policyaware_requests_total" in metrics_payload
