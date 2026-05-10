from __future__ import annotations

from policyaware.models import DataFindings, GatewayRequest, RiskAssessment, RiskTier
from policyaware.reason_codes import ReasonCode


class RiskClassifier:
    REGULATED_DOMAINS = {"healthcare", "finance", "legal", "hr", "insurance", "government"}
    HIGH_IMPACT_ACTIONS = {"write", "delete", "deploy", "purchase", "email", "permission_change"}

    def classify(self, request: GatewayRequest, findings: DataFindings) -> RiskAssessment:
        score = 0.1
        factors: list[str] = []
        reason_codes: list[str] = []

        if findings.contains_pii:
            score += 0.2
            factors.append("pii")
            reason_codes.append(ReasonCode.DATA_PII_DETECTED)
        if findings.contains_phi:
            score += 0.3
            factors.append("phi")
            reason_codes.append(ReasonCode.DATA_PHI_DETECTED)
        if findings.contains_secrets:
            score += 0.35
            factors.append("secrets")
            reason_codes.append(ReasonCode.DATA_SECRET_DETECTED)

        domain = str(request.context.get("domain", "")).lower()
        if domain in self.REGULATED_DOMAINS:
            score += 0.15
            factors.append(f"regulated_domain:{domain}")
            reason_codes.append(ReasonCode.RISK_REGULATED_DOMAIN)

        if request.tools:
            score += 0.15
            factors.append("tool_use")
            reason_codes.append(ReasonCode.RISK_TOOL_USE)

        autonomy = str(request.context.get("autonomy", "assistive")).lower()
        if autonomy in {"autonomous", "agentic"}:
            score += 0.2
            factors.append(f"autonomy:{autonomy}")
            reason_codes.append(ReasonCode.RISK_HIGH_AUTONOMY)

        business_impact = str(request.context.get("business_impact", "low")).lower()
        if business_impact == "high":
            score += 0.2
            factors.append("business_impact:high")
        elif business_impact == "critical":
            score += 0.35
            factors.append("business_impact:critical")

        action_type = str(request.context.get("action_type", "")).lower()
        if action_type in self.HIGH_IMPACT_ACTIONS:
            score += 0.25
            factors.append(f"action:{action_type}")

        declared_risk = str(request.context.get("risk", "")).lower()
        if declared_risk == "high":
            score += 0.2
            factors.append("declared_risk:high")
        elif declared_risk == "critical":
            score += 0.4
            factors.append("declared_risk:critical")

        score = min(score, 1.0)
        tier = self._tier(score)
        reason_codes.append(
            {
                RiskTier.LOW: ReasonCode.RISK_LOW,
                RiskTier.MEDIUM: ReasonCode.RISK_MEDIUM,
                RiskTier.HIGH: ReasonCode.RISK_HIGH,
                RiskTier.CRITICAL: ReasonCode.RISK_CRITICAL,
            }[tier]
        )

        return RiskAssessment(
            tier=tier,
            score=score,
            factors=factors,
            reason_codes=reason_codes,
            fail_safe="deny" if tier in {RiskTier.HIGH, RiskTier.CRITICAL} else "safe_fallback",
        )

    def _tier(self, score: float) -> RiskTier:
        if score >= 0.85:
            return RiskTier.CRITICAL
        if score >= 0.6:
            return RiskTier.HIGH
        if score >= 0.3:
            return RiskTier.MEDIUM
        return RiskTier.LOW

