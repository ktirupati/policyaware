from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from policyaware.models import Decision, GatewayRequest, PolicyDecision, RiskTier, ToolCallRequest, ToolDecision
from policyaware.policy import PolicyEngine


@dataclass(frozen=True)
class EmergencyRevokeMatch:
    matched: bool
    rule: str | None = None
    reason: str = ""


class EmergencyRevokeList:
    """High-priority deny rules evaluated before normal policy decisions."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.rules = list(self.config.get("rules", []) or [])

    @classmethod
    def from_file(cls, path: str | Path) -> "EmergencyRevokeList":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("Emergency revoke file must contain a YAML mapping/object.")
        return cls(data)

    def check_request(self, request: GatewayRequest) -> EmergencyRevokeMatch:
        context = {
            "tenant": request.tenant,
            "app": request.app,
            "user": request.user,
            "request": {**request.context, "tenant": request.tenant, "app": request.app},
            "metadata": request.metadata,
        }
        return self._match(context)

    def check_tool_call(self, request: ToolCallRequest) -> EmergencyRevokeMatch:
        context = {
            "tenant": request.tenant,
            "agent": {"id": request.agent_id},
            "user": request.user,
            "tool": {"connector": request.connector_id, "action": request.action},
            "arguments": request.arguments,
            "request": request.context,
        }
        return self._match(context)

    def deny_decision(self, match: EmergencyRevokeMatch) -> PolicyDecision:
        return PolicyDecision(
            decision=Decision.DENY,
            reason=match.reason or "Denied by emergency revoke list.",
            risk_tier=RiskTier.CRITICAL,
            risk_score=1.0,
            matched_rules=[match.rule] if match.rule else [],
            violated_rules=[match.rule] if match.rule else ["emergency_revoke"],
            reason_codes=["EMERGENCY.REVOKE_MATCHED"],
            remediation=["Review the emergency revoke list before retrying this request."],
        )

    def deny_tool_decision(self, request: ToolCallRequest, match: EmergencyRevokeMatch) -> ToolDecision:
        return ToolDecision(
            decision=Decision.DENY,
            connector_id=request.connector_id,
            action=request.action,
            reason=match.reason or "Tool call denied by emergency revoke list.",
            reason_codes=["EMERGENCY.REVOKE_MATCHED"],
            matched_rules=[match.rule] if match.rule else ["emergency_revoke"],
        )

    def _match(self, context: dict[str, Any]) -> EmergencyRevokeMatch:
        matcher = PolicyEngine({"rules": []})
        for rule in self.rules:
            if not isinstance(rule, dict):
                continue
            when = rule.get("when", {}) or {}
            if matcher._matches(when, context):
                return EmergencyRevokeMatch(
                    matched=True,
                    rule=str(rule.get("name", "emergency_revoke")),
                    reason=str(rule.get("reason", "Denied by emergency revoke list.")),
                )
        return EmergencyRevokeMatch(matched=False)

