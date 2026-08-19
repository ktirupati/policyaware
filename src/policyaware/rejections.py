from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from policyaware.models import Decision, GatewayResponse, PolicyDecision, ToolDecision


BLOCKING_DECISIONS = {Decision.DENY, Decision.REQUIRE_APPROVAL}


class PolicyAwareRejection(BaseModel):
    """Structured payload for blocked or approval-gated PolicyAware actions."""

    schema_version: str = "0.4"
    blocked: bool = True
    status_code: int = 403
    decision: str
    reason: str
    reason_codes: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    violated_rules: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    trace_id: str | None = None
    risk_tier: str | None = None
    approval_required: bool = False
    connector_id: str | None = None
    action: str | None = None
    limits: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


def is_policy_blocked(decision: PolicyDecision) -> bool:
    return decision.decision in BLOCKING_DECISIONS


def is_tool_blocked(decision: ToolDecision) -> bool:
    return decision.decision == Decision.DENY or decision.approval_required


def rejection_status_code(decision: str | Decision) -> int:
    value = decision.value if isinstance(decision, Decision) else decision
    if value == Decision.REQUIRE_APPROVAL.value:
        return 202
    if value == Decision.DENY.value:
        return 403
    return 200


def policy_rejection(response: GatewayResponse, *, status_code: int | None = None) -> PolicyAwareRejection | None:
    decision = response.policy
    if not is_policy_blocked(decision):
        return None
    return PolicyAwareRejection(
        status_code=status_code or rejection_status_code(decision.decision),
        decision=decision.decision.value,
        reason=decision.reason,
        reason_codes=decision.reason_codes,
        matched_rules=decision.matched_rules,
        violated_rules=decision.violated_rules,
        remediation=decision.remediation,
        trace_id=response.trace_id,
        risk_tier=decision.risk_tier.value,
        approval_required=decision.decision == Decision.REQUIRE_APPROVAL,
        metadata={
            "actions": decision.actions,
            "risk_score": decision.risk_score,
        },
    )


def tool_rejection(
    decision: ToolDecision,
    *,
    status_code: int | None = None,
    trace_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> PolicyAwareRejection | None:
    if not is_tool_blocked(decision):
        return None
    return PolicyAwareRejection(
        status_code=status_code or rejection_status_code(decision.decision),
        decision=decision.decision.value,
        reason=decision.reason,
        reason_codes=decision.reason_codes,
        matched_rules=decision.matched_rules,
        trace_id=trace_id,
        approval_required=decision.approval_required,
        connector_id=decision.connector_id,
        action=decision.action,
        limits=decision.limits,
        metadata=metadata or {},
    )


def rejection_event_attributes(rejection: PolicyAwareRejection) -> dict[str, Any]:
    return {
        "policyaware.blocked": rejection.blocked,
        "policyaware.status_code": rejection.status_code,
        "policyaware.decision": rejection.decision,
        "policyaware.reason": rejection.reason,
        "policyaware.reason_codes": rejection.reason_codes,
        "policyaware.matched_rules": rejection.matched_rules,
        "policyaware.trace_id": rejection.trace_id,
        "policyaware.risk_tier": rejection.risk_tier,
        "policyaware.approval_required": rejection.approval_required,
        "policyaware.connector_id": rejection.connector_id,
        "policyaware.action": rejection.action,
    }
