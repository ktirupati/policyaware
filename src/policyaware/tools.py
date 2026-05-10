from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from policyaware.models import Decision, ToolCallRequest, ToolDecision
from policyaware.policy import PolicyEngine
from policyaware.reason_codes import ReasonCode


class ToolRegistry:
    def __init__(self, connectors: dict[str, dict[str, Any]] | None = None):
        self.connectors = connectors or {}

    @classmethod
    def from_file(cls, path: str | Path) -> "ToolRegistry":
        with Path(path).open("r", encoding="utf-8") as handle:
            config = yaml.safe_load(handle) or {}
        connectors = {connector["id"]: connector for connector in config.get("connectors", [])}
        return cls(connectors)

    def connector(self, connector_id: str) -> dict[str, Any] | None:
        return self.connectors.get(connector_id)

    def action(self, connector_id: str, action: str) -> dict[str, Any] | None:
        connector = self.connector(connector_id)
        if not connector:
            return None
        return connector.get("actions", {}).get(action)


class ToolPolicyEngine:
    def __init__(self, registry: ToolRegistry, policy: dict[str, Any] | None = None):
        self.registry = registry
        self.default = (policy or {}).get("default", "deny")

    @classmethod
    def from_file(cls, path: str | Path) -> "ToolPolicyEngine":
        with Path(path).open("r", encoding="utf-8") as handle:
            config = yaml.safe_load(handle) or {}
        registry = ToolRegistry({connector["id"]: connector for connector in config.get("connectors", [])})
        return cls(registry=registry, policy=config)

    def decide(self, request: ToolCallRequest) -> ToolDecision:
        connector = self.registry.connector(request.connector_id)
        if connector is None:
            return ToolDecision(
                decision=Decision.DENY,
                connector_id=request.connector_id,
                action=request.action,
                reason="Unknown tool connector.",
                reason_codes=[ReasonCode.TOOL_CONNECTOR_UNKNOWN, ReasonCode.TOOL_DENIED],
            )

        action = self.registry.action(request.connector_id, request.action)
        if action is None:
            return ToolDecision(
                decision=Decision.DENY,
                connector_id=request.connector_id,
                action=request.action,
                reason="Unknown tool action.",
                reason_codes=[ReasonCode.TOOL_ACTION_UNKNOWN, ReasonCode.TOOL_DENIED],
            )

        context = {
            "agent": {"id": request.agent_id},
            "user": request.user,
            "tool": {
                "connector": request.connector_id,
                "action": request.action,
                "risk": action.get("risk", connector.get("risk", "medium")),
                "side_effect": action.get("side_effect", "none"),
            },
            "arguments": request.arguments,
            "request": request.context,
        }

        effect = action.get("effect", self.default)
        conditions = action.get("when", {})
        matched = PolicyEngine({"rules": []})._matches(conditions, context) if conditions else True
        if not matched:
            effect = self.default

        limits = action.get("limits", {})
        reason_codes = [ReasonCode.TOOL_RATE_LIMIT_DECLARED] if limits else []

        if effect == "allow":
            return ToolDecision(
                decision=Decision.ALLOW,
                connector_id=request.connector_id,
                action=request.action,
                reason="Tool action allowed.",
                reason_codes=[*reason_codes, ReasonCode.TOOL_ALLOWED],
                matched_rules=[f"{request.connector_id}.{request.action}"],
                limits=limits,
            )

        if effect == "require_approval":
            return ToolDecision(
                decision=Decision.REQUIRE_APPROVAL,
                connector_id=request.connector_id,
                action=request.action,
                reason="Tool action requires approval.",
                reason_codes=[*reason_codes, ReasonCode.TOOL_APPROVAL_REQUIRED],
                matched_rules=[f"{request.connector_id}.{request.action}"],
                limits=limits,
                approval_required=True,
            )

        return ToolDecision(
            decision=Decision.DENY,
            connector_id=request.connector_id,
            action=request.action,
            reason="Tool action denied by default or policy.",
            reason_codes=[*reason_codes, ReasonCode.TOOL_DENIED],
            matched_rules=[f"{request.connector_id}.{request.action}"],
            limits=limits,
        )

