from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from policyaware.data_protection import DataProtectionEngine
from policyaware.models import Decision, ToolCallRequest, ToolDecision
from policyaware.rejections import tool_rejection
from policyaware.tools import ToolPolicyEngine


class MCPJsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: str | int | None = None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class MCPProxyResult(BaseModel):
    allowed: bool
    action: str
    connector_id: str | None = None
    tool_name: str | None = None
    decision: ToolDecision | None = None
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    redactions: int = 0
    reason_codes: list[str] = Field(default_factory=list)


class MCPPolicyProxy:
    """Policy proxy core for MCP JSON-RPC tool-call messages.

    This class is transport-neutral. It can be used by a stdio proxy, HTTP bridge,
    Claude Desktop wrapper, Cursor integration, LangGraph node, or any MCP-aware
    host before the target MCP server executes a tool.
    """

    TOOL_CALL_METHOD = "tools/call"

    def __init__(
        self,
        tool_policy: ToolPolicyEngine,
        *,
        connector_id: str | None = None,
        agent_id: str = "mcp_client",
        user: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        data_protection: DataProtectionEngine | None = None,
        redact_sensitive_arguments: bool = True,
        deny_on_secrets: bool = True,
    ):
        self.tool_policy = tool_policy
        self.connector_id = connector_id
        self.agent_id = agent_id
        self.user = user or {"role": "developer"}
        self.context = context or {}
        self.data_protection = data_protection or DataProtectionEngine()
        self.redact_sensitive_arguments = redact_sensitive_arguments
        self.deny_on_secrets = deny_on_secrets

    @classmethod
    def from_policy_file(cls, path: str | Path, **kwargs: Any) -> "MCPPolicyProxy":
        return cls(ToolPolicyEngine.from_file(path), **kwargs)

    def evaluate(self, payload: dict[str, Any] | MCPJsonRpcRequest) -> MCPProxyResult:
        request = payload if isinstance(payload, MCPJsonRpcRequest) else MCPJsonRpcRequest(**payload)
        raw = request.model_dump(mode="json")

        if request.method != self.TOOL_CALL_METHOD:
            return MCPProxyResult(
                allowed=True,
                action="pass_through",
                request=raw,
                reason_codes=["MCP.PASSTHROUGH"],
            )

        tool_name = str(request.params.get("name") or "")
        connector_id, action = self._split_tool_name(tool_name)
        arguments = dict(request.params.get("arguments") or {})
        findings = self.data_protection.inspect(json.dumps(arguments, sort_keys=True, default=str))

        if self.deny_on_secrets and findings.contains_secrets:
            decision = ToolDecision(
                decision=Decision.DENY,
                connector_id=connector_id,
                action=action,
                reason="MCP tool call arguments contained secrets.",
                reason_codes=["MCP.ARGUMENT_SECRET_DETECTED", "TOOL.DENIED"],
                matched_rules=[f"{connector_id}.{action}"],
            )
            return self._blocked_result(request, connector_id, tool_name, decision)

        decision = self.tool_policy.decide(
            ToolCallRequest(
                agent_id=self.agent_id,
                connector_id=connector_id,
                action=action,
                arguments=arguments,
                user=self.user,
                context={
                    **self.context,
                    "mcp_method": request.method,
                    "mcp_tool_name": tool_name,
                    "mcp_request_id": request.id,
                },
            )
        )

        if decision.decision == Decision.DENY or decision.approval_required:
            return self._blocked_result(request, connector_id, tool_name, decision)

        sanitized_arguments = arguments
        redactions = 0
        if self.redact_sensitive_arguments and findings.contains_sensitive:
            sanitized_arguments, redactions = self._redact_value(arguments)

        forwarded = request.model_dump(mode="json")
        forwarded["params"] = dict(forwarded.get("params") or {})
        forwarded["params"]["arguments"] = sanitized_arguments
        return MCPProxyResult(
            allowed=True,
            action="forward",
            connector_id=connector_id,
            tool_name=tool_name,
            decision=decision,
            request=forwarded,
            redactions=redactions,
            reason_codes=[*decision.reason_codes, "MCP.TOOL_CALL_ALLOWED"],
        )

    def _split_tool_name(self, tool_name: str) -> tuple[str, str]:
        if "." in tool_name:
            connector, action = tool_name.split(".", 1)
            return connector, action
        if "/" in tool_name:
            connector, action = tool_name.split("/", 1)
            return connector, action
        return self.connector_id or "mcp", tool_name

    def _blocked_result(
        self,
        request: MCPJsonRpcRequest,
        connector_id: str,
        tool_name: str,
        decision: ToolDecision,
    ) -> MCPProxyResult:
        rejection = tool_rejection(
            decision,
            metadata={
                "mcp_method": request.method,
                "mcp_tool_name": tool_name,
                "mcp_request_id": request.id,
            },
        )
        response = {
            "jsonrpc": "2.0",
            "id": request.id,
            "error": {
                "code": -32001 if decision.approval_required else -32000,
                "message": decision.reason,
                "data": rejection.model_dump(mode="json") if rejection else decision.model_dump(mode="json"),
            },
        }
        return MCPProxyResult(
            allowed=False,
            action="block",
            connector_id=connector_id,
            tool_name=tool_name,
            decision=decision,
            response=response,
            reason_codes=decision.reason_codes,
        )

    def _redact_value(self, value: Any) -> tuple[Any, int]:
        if isinstance(value, str):
            findings = self.data_protection.redact(value)
            return findings.redacted_text if findings.redacted_text is not None else value, findings.redactions
        if isinstance(value, list):
            redacted_items = []
            total = 0
            for item in value:
                redacted, count = self._redact_value(item)
                redacted_items.append(redacted)
                total += count
            return redacted_items, total
        if isinstance(value, dict):
            redacted_dict: dict[str, Any] = {}
            total = 0
            for key, item in value.items():
                redacted, count = self._redact_value(item)
                redacted_dict[key] = redacted
                total += count
            return redacted_dict, total
        return value, 0
