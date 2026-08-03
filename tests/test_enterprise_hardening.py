from __future__ import annotations

from pathlib import Path

import pytest

from policyaware import (
    AuditLogger,
    EmergencyRevokeList,
    Gateway,
    GatewayRequest,
    IntegritySigner,
    PolicyAwareSidecar,
    PolicySourceError,
    SQLiteSessionStateStore,
    SessionStateMonitor,
)
from policyaware.policy_source import policy_source_from_uri
from policyaware.tools import ToolPolicyEngine


ROOT = Path(__file__).resolve().parents[1]


def test_sqlite_session_state_persists_across_monitors(tmp_path: Path) -> None:
    db = tmp_path / "session.db"
    first_monitor = SessionStateMonitor(
        max_sensitive_findings_per_session=1,
        store=SQLiteSessionStateStore(db),
    )
    second_monitor = SessionStateMonitor(
        max_sensitive_findings_per_session=1,
        store=SQLiteSessionStateStore(db),
    )
    gateway_one = Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml")
    gateway_two = Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml")
    gateway_one.session_monitor = first_monitor
    gateway_two.session_monitor = second_monitor

    first = gateway_one.chat(_request("Email jane@example.com", "shared-session"))
    second = gateway_two.chat(_request("Call 212-555-7890", "shared-session"))

    assert first.policy.decision.value in {"allow", "conditional_allow"}
    assert second.policy.decision.value == "deny"
    assert "SESSION.CUMULATIVE_SENSITIVE_DATA" in second.policy.reason_codes


def test_emergency_revoke_denies_gateway_request(tmp_path: Path) -> None:
    revoke_file = tmp_path / "revoke.yaml"
    revoke_file.write_text(
        """
rules:
  - name: revoke_support_agent
    reason: Emergency support-agent shutdown.
    when:
      user.role: support_agent
""",
        encoding="utf-8",
    )
    gateway = Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml")
    gateway.emergency_revoke = EmergencyRevokeList.from_file(revoke_file)

    response = gateway.chat(_request("Summarize this ticket.", "revoked-session"))

    assert response.policy.decision.value == "deny"
    assert response.policy.matched_rules == ["revoke_support_agent"]
    assert "EMERGENCY.REVOKE_MATCHED" in response.policy.reason_codes


def test_emergency_revoke_denies_sidecar_tool_call(tmp_path: Path) -> None:
    revoke_file = tmp_path / "revoke.yaml"
    revoke_file.write_text(
        """
rules:
  - name: revoke_github_reads
    reason: Emergency GitHub read shutdown.
    when:
      tool.connector: github
      tool.action: read_file
""",
        encoding="utf-8",
    )
    gateway = Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml")
    sidecar = PolicyAwareSidecar(
        gateway,
        ToolPolicyEngine.from_file(ROOT / "examples" / "policies" / "tool-governance.yaml"),
        emergency_revoke=EmergencyRevokeList.from_file(revoke_file),
    )

    status, payload = sidecar.handle(
        "POST",
        "/v1/tool/check",
        {
            "agent_id": "code_assistant",
            "connector_id": "github",
            "action": "read_file",
            "user": {"role": "developer"},
        },
    )

    assert status == 200
    assert payload["decision"] == "deny"
    assert payload["matched_rules"] == ["revoke_github_reads"]


def test_policy_source_checksum_pin_rejects_mismatch(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("default: deny\nrules: []\n", encoding="utf-8")

    source = policy_source_from_uri(policy, expected_sha256="bad")
    with pytest.raises(PolicySourceError):
        source.load()

    remote = policy_source_from_uri(
        "https://policy.example.invalid/policy.yaml",
        cache_file=policy,
        expected_sha256="bad",
    )
    with pytest.raises(PolicySourceError):
        remote.load()


def test_integrity_signer_verifies_audit_payload(tmp_path: Path) -> None:
    signer = IntegritySigner("secret")
    logger = AuditLogger(tmp_path / "traces.jsonl", signer=signer)
    gateway = Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml")
    gateway.audit_logger = logger

    gateway.chat(_request("Summarize this ticket.", "signed-session"))
    trace = logger.read_traces()[0]
    signature = trace.pop("integrity")

    assert signer.verify(trace, signature)
    trace["policy_decision"] = "allow" if trace["policy_decision"] != "allow" else "deny"
    assert not signer.verify(trace, signature)


def _request(prompt: str, session_id: str) -> GatewayRequest:
    return GatewayRequest(
        tenant="acme",
        app="hardening-test",
        user={"id": "u_123", "role": "support_agent"},
        context={"region": "us", "risk": "low", "task_type": "support", "session_id": session_id},
        messages=[{"role": "user", "content": prompt}],
    )
