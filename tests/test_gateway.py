from pathlib import Path

from policyaware import Gateway, GatewayRequest
from policyaware.models import Decision


def test_gateway_allows_and_audits(tmp_path: Path) -> None:
    gateway = Gateway.from_policy_file("examples/policies/basic.yaml")
    gateway.audit_logger.path = tmp_path / "traces.jsonl"

    response = gateway.chat(
        GatewayRequest(
            tenant="acme",
            app="test",
            user={"id": "u1", "role": "support_agent"},
            context={"region": "us", "risk": "low", "task_type": "summarization"},
            messages=[{"role": "user", "content": "Summarize this ticket."}],
        )
    )

    assert response.policy.decision == Decision.ALLOW
    assert response.route is not None
    assert response.risk is not None
    assert "POLICY.ALLOW_MATCHED" in response.policy.reason_codes
    assert (tmp_path / "traces.jsonl").exists()


def test_gateway_blocks_secrets() -> None:
    gateway = Gateway.from_policy_file("examples/policies/basic.yaml")
    response = gateway.chat(
        GatewayRequest(
            tenant="acme",
            app="test",
            user={"id": "u1", "role": "support_agent"},
            context={"region": "us", "risk": "low", "task_type": "summarization"},
            messages=[{"role": "user", "content": "Use secret_api_key_abcdefghijklmnop"}],
        )
    )

    assert response.policy.decision == Decision.DENY
    assert "DATA.SECRET_DETECTED" in response.policy.reason_codes


def test_gateway_inspect_and_mutate_redacts_pii(tmp_path: Path) -> None:
    gateway = Gateway.from_policy_file("examples/zero-config-openai/policy.yaml")
    gateway.audit_logger.path = tmp_path / "traces.jsonl"

    safe_prompt, metadata = gateway.inspect_and_mutate(
        "Email jane@example.com about claim ACME-42.",
        context={"user_role": "billing_admin", "risk": "low"},
        app="zero-config",
    )

    assert "jane@example.com" not in safe_prompt
    assert metadata["allowed"] is True
    assert metadata["decision"] == Decision.CONDITIONAL_ALLOW.value
    assert "redact" in metadata["actions"]
    assert metadata["redactions"] >= 1
    assert (tmp_path / "traces.jsonl").exists()


def test_gateway_inspect_and_mutate_fails_closed_on_secret(tmp_path: Path) -> None:
    gateway = Gateway.from_policy_file("examples/zero-config-openai/policy.yaml")
    gateway.audit_logger.path = tmp_path / "traces.jsonl"

    try:
        gateway.inspect_and_mutate(
            "Use secret_api_key_abcdefghijklmnop",
            context={"user_role": "billing_admin", "risk": "low"},
            app="zero-config",
        )
    except PermissionError as exc:
        assert "Blocked by PolicyAware" in str(exc)
    else:
        raise AssertionError("Expected fail-closed PermissionError")

    assert (tmp_path / "traces.jsonl").exists()
