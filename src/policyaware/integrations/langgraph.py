from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from policyaware.gateway import Gateway
from policyaware.models import Decision, GatewayRequest, GatewayResponse, ToolCallRequest, ToolDecision
from policyaware.tools import ToolPolicyEngine


@dataclass
class PolicyAwareNodeResult:
    """Governance result for a LangGraph node/state transition."""

    allowed: bool
    decision: str
    response: GatewayResponse
    state_update: dict[str, Any] = field(default_factory=dict)

    @property
    def requires_approval(self) -> bool:
        return self.decision == Decision.REQUIRE_APPROVAL.value


class PolicyAwareNodeGuard:
    """Dependency-free guard for LangGraph-style nodes.

    LangGraph nodes are ordinary Python callables. This wrapper lets developers
    evaluate graph state before a node runs, guard tool calls, and optionally
    wrap sync or async node functions without adding LangGraph as a dependency.
    """

    def __init__(
        self,
        config: str | Path | None = None,
        gateway: Gateway | None = None,
        tool_policy: str | Path | ToolPolicyEngine | None = None,
        *,
        tenant: str = "default",
        app: str = "langgraph-agent",
        default_user: dict[str, Any] | None = None,
        default_context: dict[str, Any] | None = None,
        denied_message: str = "Request blocked by PolicyAware policy.",
        approval_message: str = "Request requires approval before this graph node can continue.",
    ):
        if gateway is None and config is None:
            raise ValueError("PolicyAwareNodeGuard requires config='policy.yaml' or gateway=Gateway(...).")
        self.gateway = gateway or Gateway.from_policy_file(config)  # type: ignore[arg-type]
        if isinstance(tool_policy, ToolPolicyEngine):
            self.tool_engine = tool_policy
        elif tool_policy is not None:
            self.tool_engine = ToolPolicyEngine.from_file(tool_policy)
        else:
            self.tool_engine = None
        self.tenant = tenant
        self.app = app
        self.default_user = default_user or {"role": "developer"}
        self.default_context = default_context or {
            "region": "us",
            "task_type": "langgraph_node",
            "risk": "low",
        }
        self.denied_message = denied_message
        self.approval_message = approval_message
        self.last_result: PolicyAwareNodeResult | None = None
        self.last_tool_decision: ToolDecision | None = None

    def check_state(self, state: dict[str, Any], **metadata: Any) -> PolicyAwareNodeResult:
        request = self.to_gateway_request(state, metadata=metadata)
        response = self.gateway.chat(request)
        decision = response.policy.decision.value
        allowed = decision in {Decision.ALLOW.value, Decision.CONDITIONAL_ALLOW.value}
        state_update: dict[str, Any] = {
            "policyaware": {
                "allowed": allowed,
                "decision": decision,
                "trace_id": response.trace_id,
                "reason_codes": response.policy.reason_codes,
                "matched_rules": response.policy.matched_rules,
                "risk_tier": response.policy.risk_tier.value,
            }
        }
        if decision == Decision.DENY.value:
            state_update["messages"] = [{"role": "assistant", "content": self.denied_message}]
        elif decision == Decision.REQUIRE_APPROVAL.value:
            state_update["messages"] = [{"role": "assistant", "content": self.approval_message}]
            state_update["policyaware"]["approval_required"] = True
        self.last_result = PolicyAwareNodeResult(
            allowed=allowed,
            decision=decision,
            response=response,
            state_update=state_update,
        )
        return self.last_result

    def guard_node(self, node: Callable[[dict[str, Any]], Any]) -> Callable[[dict[str, Any]], Any]:
        """Wrap a sync or async LangGraph node with a pre-node policy check."""

        if inspect.iscoroutinefunction(node):

            async def async_wrapped(state: dict[str, Any]) -> Any:
                result = self.check_state(state)
                if not result.allowed:
                    return result.state_update
                output = node(state)
                return await output  # type: ignore[misc]

            return async_wrapped

        def wrapped(state: dict[str, Any]) -> Any:
            result = self.check_state(state)
            if not result.allowed:
                return result.state_update
            return node(state)

        return wrapped

    async def aguard_node(
        self, node: Callable[[dict[str, Any]], Awaitable[Any]], state: dict[str, Any]
    ) -> Any:
        """Run an async node with a policy check in front of it."""

        result = self.check_state(state)
        if not result.allowed:
            return result.state_update
        return await node(state)

    def check_tool_call(
        self,
        *,
        agent_id: str,
        connector_id: str,
        action: str,
        arguments: dict[str, Any] | None = None,
        state: dict[str, Any] | None = None,
        user: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ToolDecision:
        if self.tool_engine is None:
            raise ValueError("Tool governance requires tool_policy='tool-governance.yaml'.")
        decision = self.tool_engine.decide(
            ToolCallRequest(
                agent_id=agent_id,
                connector_id=connector_id,
                action=action,
                arguments=arguments or {},
                tenant=str((state or {}).get("tenant", self.tenant)),
                user=user or _state_user(state) or self.default_user,
                context={**self.default_context, **(context or {}), **_state_context(state)},
            )
        )
        self.last_tool_decision = decision
        return decision

    def to_gateway_request(
        self, state: dict[str, Any], *, metadata: dict[str, Any] | None = None
    ) -> GatewayRequest:
        return GatewayRequest(
            tenant=str(state.get("tenant", self.tenant)),
            app=str(state.get("app", self.app)),
            user=_state_user(state) or self.default_user,
            context={**self.default_context, **_state_context(state)},
            messages=_state_messages(state),
            tools=list(state.get("tools", [])) if isinstance(state.get("tools", []), list) else [],
            metadata={**dict(state.get("metadata", {})), **(metadata or {})},
        )


def _state_messages(state: dict[str, Any]) -> list[dict[str, str]]:
    messages = state.get("messages")
    if isinstance(messages, list):
        normalized: list[dict[str, str]] = []
        for item in messages:
            if isinstance(item, dict):
                normalized.append(
                    {
                        "role": str(item.get("role", "user")),
                        "content": str(item.get("content", item.get("text", ""))),
                    }
                )
            else:
                content = getattr(item, "content", None) or getattr(item, "text", None) or str(item)
                role = getattr(item, "role", None) or "user"
                normalized.append({"role": str(role), "content": str(content)})
        return normalized
    for key in ("prompt", "input", "query", "question"):
        if state.get(key):
            return [{"role": "user", "content": str(state[key])}]
    return [{"role": "user", "content": ""}]


def _state_user(state: dict[str, Any] | None) -> dict[str, Any] | None:
    if not state:
        return None
    user = state.get("user")
    if isinstance(user, dict):
        return user
    role = state.get("role") or state.get("user_role")
    if role:
        return {"role": str(role)}
    return None


def _state_context(state: dict[str, Any] | None) -> dict[str, Any]:
    if not state:
        return {}
    context = state.get("context")
    if isinstance(context, dict):
        return context
    context_keys = ("region", "risk", "task_type", "domain", "autonomy", "action_type")
    return {key: state[key] for key in context_keys if key in state}
