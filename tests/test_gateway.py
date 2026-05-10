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
