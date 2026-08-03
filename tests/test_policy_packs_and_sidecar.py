from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from policyaware import Gateway, GatewayRequest, PolicyAwareSidecar
from policyaware.cli import app
from policyaware.policy_pack_registry import copy_policy_pack, list_policy_packs, read_policy_pack
from policyaware.policy_schema import PolicySchemaValidator
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

    assert health_status == 200
    assert missing_status == 401
    assert missing_payload["error"] == "unauthorized"
    assert wrong_status == 401
    assert ok_status == 200
    assert ok_payload["decision"] in {"allow", "conditional_allow"}
