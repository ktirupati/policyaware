from __future__ import annotations

from policyaware import Decision, ToolDecision
from policyaware.integrations.microsoft_agt import (
    AGT_SCHEMA_VERSION,
    to_agt_audit_evidence,
    to_agt_decision,
    to_agt_tool_evidence,
)
from policyaware.models import PolicyDecision, RiskTier


def test_policy_decision_maps_to_agt_permit() -> None:
    decision = PolicyDecision(
        decision=Decision.CONDITIONAL_ALLOW,
        actions=["redact"],
        matched_rules=["allow_support", "redact_pii"],
        reason="Allowed with transforms.",
        risk_tier=RiskTier.MEDIUM,
        reason_codes=["DATA.PII_DETECTED", "POLICY.TRANSFORM_APPLIED"],
    )

    evidence = to_agt_decision(decision)

    assert evidence["schema"] == AGT_SCHEMA_VERSION
    assert evidence["decision"] == "permit"
    assert evidence["policyaware_decision"] == "conditional_allow"
    assert evidence["enforcement"]["allowed"] is True
    assert evidence["metadata"]["actions"] == ["redact"]


def test_tool_decision_maps_to_agt_review() -> None:
    decision = ToolDecision(
        decision=Decision.REQUIRE_APPROVAL,
        connector_id="github",
        action="create_pr",
        reason="Tool action requires approval.",
        reason_codes=["TOOL.APPROVAL_REQUIRED"],
        matched_rules=["github.create_pr"],
        approval_required=True,
    )

    evidence = to_agt_tool_evidence(
        decision,
        agent_id="agent_1",
        tenant="acme",
        user={"role": "developer"},
        arguments={"title": "Update docs"},
    )

    assert evidence["decision"] == "review"
    assert evidence["enforcement"]["approval_required"] is True
    assert evidence["subject"]["agent_id"] == "agent_1"
    assert evidence["action"]["connector_id"] == "github"
    assert evidence["action"]["arguments"]["title"] == "Update docs"


def test_denied_tool_decision_maps_to_agt_deny() -> None:
    decision = ToolDecision(
        decision=Decision.DENY,
        connector_id="database",
        action="drop_table",
        reason="Tool action denied by default or policy.",
        reason_codes=["TOOL.DENIED"],
        matched_rules=["database.drop_table"],
    )

    evidence = to_agt_decision(decision)

    assert evidence["decision"] == "deny"
    assert evidence["enforcement"]["blocked"] is True
    assert evidence["metadata"]["connector_id"] == "database"


def test_audit_trace_dict_maps_to_agt_evidence() -> None:
    evidence = to_agt_audit_evidence(
        {
            "trace_id": "trc_1",
            "tenant": "acme",
            "app": "support",
            "user_id": "u_1",
            "policy_decision": "deny",
            "risk_tier": "high",
            "risk_score": 0.8,
            "model": "local/sim-small",
            "task_type": "support",
            "reason_codes": ["POLICY.DENY_MATCHED"],
            "matched_rules": ["block_secrets"],
        }
    )

    assert evidence["decision"] == "deny"
    assert evidence["subject"]["tenant"] == "acme"
    assert evidence["risk"]["tier"] == "high"
    assert evidence["trace"]["trace_id"] == "trc_1"
