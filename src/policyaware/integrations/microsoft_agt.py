from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from policyaware.models import AuditTrace, Decision, GatewayResponse, PolicyDecision, ToolDecision


AGT_SCHEMA_VERSION = "policyaware.microsoft_agt.evidence.v1"


def to_agt_decision(decision: PolicyDecision | ToolDecision) -> dict[str, Any]:
    """Convert a PolicyAware decision into Microsoft AGT-style evidence JSON.

    The output is intentionally dependency-free and schema-labeled as PolicyAware
    interop. It is not a Microsoft-owned wire contract.
    """

    decision_value = decision.decision.value
    return {
        "schema": AGT_SCHEMA_VERSION,
        "evidence_id": f"agt_ev_{uuid4().hex}",
        "created_at": _now(),
        "decision": _decision_to_agt_outcome(decision.decision),
        "policyaware_decision": decision_value,
        "enforcement": {
            "allowed": decision.decision in {Decision.ALLOW, Decision.CONDITIONAL_ALLOW},
            "approval_required": decision.decision == Decision.REQUIRE_APPROVAL
            or getattr(decision, "approval_required", False),
            "blocked": decision.decision == Decision.DENY,
        },
        "reason": decision.reason,
        "reason_codes": list(decision.reason_codes),
        "matched_rules": list(decision.matched_rules),
        "metadata": _decision_metadata(decision),
    }


def to_agt_tool_evidence(
    decision: ToolDecision,
    *,
    agent_id: str | None = None,
    arguments: dict[str, Any] | None = None,
    tenant: str = "default",
    user: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = to_agt_decision(decision)
    evidence["subject"] = {
        "type": "agent_tool_call",
        "agent_id": agent_id,
        "tenant": tenant,
        "user": user or {},
    }
    evidence["action"] = {
        "connector_id": decision.connector_id,
        "name": decision.action,
        "arguments": arguments or {},
        "context": context or {},
    }
    evidence["controls"] = {
        "limits": decision.limits,
        "approval_required": decision.approval_required,
    }
    return evidence


def to_agt_gateway_evidence(response: GatewayResponse) -> dict[str, Any]:
    evidence = to_agt_decision(response.policy)
    evidence["subject"] = {"type": "llm_request"}
    evidence["action"] = {
        "type": "model_call",
        "model": response.route.model.name if response.route else None,
        "provider": response.route.model.provider if response.route else None,
    }
    evidence["risk"] = response.risk.model_dump(mode="json") if response.risk else None
    evidence["evals"] = [result.model_dump(mode="json") for result in response.evals]
    evidence["trace_id"] = response.trace_id
    return evidence


def to_agt_audit_evidence(trace: AuditTrace | dict[str, Any]) -> dict[str, Any]:
    trace_data = trace.model_dump(mode="json") if isinstance(trace, AuditTrace) else dict(trace)
    return {
        "schema": AGT_SCHEMA_VERSION,
        "evidence_id": f"agt_ev_{uuid4().hex}",
        "created_at": _now(),
        "decision": _decision_to_agt_outcome(Decision(trace_data.get("policy_decision", "deny"))),
        "policyaware_decision": trace_data.get("policy_decision"),
        "subject": {
            "type": "audit_trace",
            "tenant": trace_data.get("tenant"),
            "app": trace_data.get("app"),
            "user_id": trace_data.get("user_id"),
        },
        "risk": {
            "tier": trace_data.get("risk_tier"),
            "score": trace_data.get("risk_score"),
        },
        "action": {
            "type": "model_call",
            "model": trace_data.get("model"),
            "task_type": trace_data.get("task_type"),
        },
        "enforcement": {
            "allowed": trace_data.get("policy_decision") in {"allow", "conditional_allow"},
            "approval_required": trace_data.get("policy_decision") == "require_approval",
            "blocked": trace_data.get("policy_decision") == "deny",
        },
        "reason_codes": trace_data.get("reason_codes", []),
        "matched_rules": trace_data.get("matched_rules", []),
        "trace": trace_data,
    }


def _decision_to_agt_outcome(decision: Decision) -> str:
    if decision in {Decision.ALLOW, Decision.CONDITIONAL_ALLOW}:
        return "permit"
    if decision == Decision.REQUIRE_APPROVAL:
        return "review"
    return "deny"


def _decision_metadata(decision: PolicyDecision | ToolDecision) -> dict[str, Any]:
    if isinstance(decision, PolicyDecision):
        return {
            "risk_score": decision.risk_score,
            "risk_tier": decision.risk_tier.value,
            "actions": decision.actions,
            "violated_rules": decision.violated_rules,
            "remediation": decision.remediation,
        }
    return {
        "connector_id": decision.connector_id,
        "action": decision.action,
        "limits": decision.limits,
        "approval_required": decision.approval_required,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
