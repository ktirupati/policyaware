from __future__ import annotations

from pathlib import Path

from policyaware import AuditLogger, Gateway, GatewayRequest, GovernanceDashboard, PolicyRollout


ROOT = Path(__file__).resolve().parents[1]


def test_policy_rollout_shadow_adds_candidate_metadata(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.yaml"
    candidate.write_text(
        """
default: deny
rules:
  - name: deny_support_shadow
    effect: deny
    when:
      user.role: support_agent
""",
        encoding="utf-8",
    )
    gateway = Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml")
    gateway.policy_rollout = PolicyRollout.from_file(candidate, mode="shadow", percentage=100)

    response = gateway.chat(_request("Summarize this ticket."))

    assert response.policy.decision.value in {"allow", "conditional_allow"}
    assert response.metadata["policy_rollout"]["mode"] == "shadow"
    assert response.metadata["policy_rollout"]["candidate_decision"] == "deny"
    assert response.metadata["policy_rollout"]["changed"] is True


def test_policy_rollout_enforce_uses_candidate_policy(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.yaml"
    candidate.write_text(
        """
default: deny
rules:
  - name: deny_support_enforced
    effect: deny
    when:
      user.role: support_agent
""",
        encoding="utf-8",
    )
    gateway = Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml")
    gateway.policy_rollout = PolicyRollout.from_file(candidate, mode="enforce", percentage=100)

    response = gateway.chat(_request("Summarize this ticket."))

    assert response.policy.decision.value == "deny"
    assert response.metadata["policy_rollout"]["mode"] == "enforce"
    assert response.metadata["policy_rollout"]["candidate_decision"] == "deny"


def test_audit_trace_correlation_and_dashboard(tmp_path: Path) -> None:
    traces = tmp_path / "traces.jsonl"
    dashboard = tmp_path / "dashboard.html"
    gateway = Gateway.from_policy_file(ROOT / "examples" / "policies" / "basic.yaml")
    gateway.audit_logger = AuditLogger(traces)

    gateway.chat(_request("Summarize this ticket."))
    trace = gateway.audit_logger.read_traces()[0]
    output = GovernanceDashboard().write_html([trace], dashboard)

    assert trace["parent_trace_id"] == "trc_parent"
    assert trace["session_id"] == "session-42"
    assert output.exists()
    assert "PolicyAware Governance Dashboard" in output.read_text(encoding="utf-8")


def _request(prompt: str) -> GatewayRequest:
    return GatewayRequest(
        tenant="acme",
        app="rollout-test",
        user={"id": "u_123", "role": "support_agent"},
        context={
            "region": "us",
            "risk": "low",
            "task_type": "support",
            "session_id": "session-42",
            "parent_trace_id": "trc_parent",
        },
        messages=[{"role": "user", "content": prompt}],
    )

