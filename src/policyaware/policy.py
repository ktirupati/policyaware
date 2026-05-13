from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from policyaware.models import (
    DataFindings,
    Decision,
    DecisionExplanation,
    GatewayRequest,
    PolicyDecision,
    RiskAssessment,
    RiskTier,
)
from policyaware.policy_schema import PolicySchemaValidator
from policyaware.reason_codes import ReasonCode


@dataclass(frozen=True)
class PolicyRule:
    name: str
    effect: str
    when: dict[str, Any]
    action: str | None = None


class PolicyEngine:
    def __init__(self, policy: dict[str, Any]):
        PolicySchemaValidator().validate(policy)
        self.policy = policy
        self.default = policy.get("default", "deny")
        self.rules = [
            PolicyRule(
                name=rule["name"],
                effect=rule["effect"],
                when=rule.get("when", {}),
                action=rule.get("action"),
            )
            for rule in policy.get("rules", [])
        ]

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        with Path(path).open("r", encoding="utf-8") as handle:
            return cls(yaml.safe_load(handle) or {})

    def decide(
        self,
        request: GatewayRequest,
        findings: DataFindings,
        risk: RiskAssessment | None = None,
    ) -> PolicyDecision:
        risk = risk or self._legacy_risk(request, findings)
        context = self._context(request, findings, risk)
        matched: list[PolicyRule] = [rule for rule in self.rules if self._matches(rule.when, context)]

        deny_rules = [rule for rule in matched if rule.effect == "deny"]
        if deny_rules:
            decision = PolicyDecision(
                decision=Decision.DENY,
                matched_rules=[rule.name for rule in deny_rules],
                violated_rules=[rule.name for rule in deny_rules],
                reason="Denied by matching policy rule.",
                risk_score=risk.score,
                risk_tier=risk.tier,
                reason_codes=[*risk.reason_codes, ReasonCode.POLICY_DENY_MATCHED],
                remediation=["Review the matched deny policy or remove sensitive/risky inputs."],
            )
            return self._with_explanation(decision)

        approval_rules = [rule for rule in matched if rule.effect == "require_approval"]
        if approval_rules:
            decision = PolicyDecision(
                decision=Decision.REQUIRE_APPROVAL,
                actions=["require_approval"],
                matched_rules=[rule.name for rule in approval_rules],
                reason="Request requires human approval before execution.",
                risk_score=risk.score,
                risk_tier=risk.tier,
                reason_codes=[*risk.reason_codes, ReasonCode.POLICY_APPROVAL_REQUIRED],
                remediation=["Route this request to an approval workflow before execution."],
            )
            return self._with_explanation(decision)

        transform_rules = [rule for rule in matched if rule.effect == "transform"]
        allow_rules = [rule for rule in matched if rule.effect == "allow"]

        if allow_rules:
            actions = [rule.action for rule in transform_rules if rule.action]
            reason_codes = [*risk.reason_codes, ReasonCode.POLICY_ALLOW_MATCHED]
            if actions:
                reason_codes.append(ReasonCode.POLICY_TRANSFORM_APPLIED)
            decision = PolicyDecision(
                decision=Decision.CONDITIONAL_ALLOW if actions else Decision.ALLOW,
                actions=actions,
                matched_rules=[rule.name for rule in [*allow_rules, *transform_rules]],
                reason="Allowed by matching policy rule." if not actions else "Allowed with transforms.",
                risk_score=risk.score,
                risk_tier=risk.tier,
                reason_codes=reason_codes,
                remediation=[] if not actions else ["Transforms were applied before execution."],
            )
            return self._with_explanation(decision)

        if self.default == "allow":
            actions = [rule.action for rule in transform_rules if rule.action]
            reason_codes = [*risk.reason_codes, ReasonCode.POLICY_ALLOW_MATCHED]
            if actions:
                reason_codes.append(ReasonCode.POLICY_TRANSFORM_APPLIED)
            decision = PolicyDecision(
                decision=Decision.CONDITIONAL_ALLOW if actions else Decision.ALLOW,
                actions=actions,
                matched_rules=[rule.name for rule in transform_rules],
                reason="Allowed by default policy." if not actions else "Allowed by default with transforms.",
                risk_score=risk.score,
                risk_tier=risk.tier,
                reason_codes=reason_codes,
            )
            return self._with_explanation(decision)

        decision = PolicyDecision(
            decision=Decision.DENY,
            reason="Denied by default because no allow rule matched.",
            risk_score=risk.score,
            risk_tier=risk.tier,
            reason_codes=[*risk.reason_codes, ReasonCode.POLICY_DEFAULT_DENY],
            remediation=["Add an explicit allow rule for this role, task type, tenant, and risk tier."],
        )
        return self._with_explanation(decision)

    def _context(
        self, request: GatewayRequest, findings: DataFindings, risk: RiskAssessment
    ) -> dict[str, Any]:
        return {
            "tenant": request.tenant,
            "app": request.app,
            "user": request.user,
            "request": {
                **request.context,
                "tenant": request.tenant,
                "app": request.app,
                "tools_requested": bool(request.tools),
            },
            "data": {
                "contains_pii": findings.contains_pii,
                "contains_phi": findings.contains_phi,
                "contains_secrets": findings.contains_secrets,
                "contains_sensitive": findings.contains_sensitive,
                "categories": findings.categories,
            },
            "risk": {
                "tier": risk.tier.value,
                "score": risk.score,
                "factors": risk.factors,
            },
            "ml": request.metadata.get("ml", {}),
        }

    def _matches(self, expected: dict[str, Any], actual: dict[str, Any]) -> bool:
        for dotted_key, expected_value in expected.items():
            operator = "eq"
            key = dotted_key
            for suffix, op in {
                "_not_in": "not_in",
                "_in": "in",
                "_lte": "lte",
                "_gte": "gte",
            }.items():
                if dotted_key.endswith(suffix):
                    key = dotted_key[: -len(suffix)]
                    operator = op
                    break

            actual_value = self._lookup(actual, key)
            if not self._compare(actual_value, expected_value, operator):
                return False
        return True

    def _lookup(self, source: dict[str, Any], dotted_key: str) -> Any:
        current: Any = source
        for part in dotted_key.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current

    def _compare(self, actual: Any, expected: Any, operator: str) -> bool:
        if operator == "in":
            return actual in expected
        if operator == "not_in":
            return actual not in expected
        if operator == "lte":
            return actual is not None and actual <= expected
        if operator == "gte":
            return actual is not None and actual >= expected
        return actual == expected

    def _legacy_risk(self, request: GatewayRequest, findings: DataFindings) -> RiskAssessment:
        score = 0.1
        factors: list[str] = []
        reason_codes: list[str] = []
        if findings.contains_pii:
            score += 0.2
            factors.append("pii")
            reason_codes.append(ReasonCode.DATA_PII_DETECTED)
        if findings.contains_phi:
            score += 0.25
            factors.append("phi")
            reason_codes.append(ReasonCode.DATA_PHI_DETECTED)
        if findings.contains_secrets:
            score += 0.3
            factors.append("secrets")
            reason_codes.append(ReasonCode.DATA_SECRET_DETECTED)
        if request.tools:
            score += 0.15
            factors.append("tool_use")
            reason_codes.append(ReasonCode.RISK_TOOL_USE)
        if request.context.get("risk") == "high":
            score += 0.25
            factors.append("declared_risk:high")
        score = min(score, 1.0)
        tier = RiskTier.HIGH if score >= 0.6 else RiskTier.MEDIUM if score >= 0.3 else RiskTier.LOW
        return RiskAssessment(tier=tier, score=score, factors=factors, reason_codes=reason_codes)

    def _with_explanation(self, decision: PolicyDecision) -> PolicyDecision:
        summary = f"{decision.decision.value}: {decision.reason}"
        decision.explanation = DecisionExplanation(
            decision=decision.decision,
            summary=summary,
            reason_codes=decision.reason_codes,
            matched_policy_ids=decision.matched_rules,
            violated_policy_ids=decision.violated_rules,
            remediation=decision.remediation,
        )
        return decision
