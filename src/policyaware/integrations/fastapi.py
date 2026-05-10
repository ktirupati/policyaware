from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from policyaware.gateway import Gateway
from policyaware.models import GatewayRequest


class PolicyAwareMiddleware:
    """ASGI middleware that annotates requests with a policy probe decision.

    Applications can inspect ``scope["policyaware.decision"]`` before invoking model code.
    """

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        gateway: Gateway,
        tenant_resolver: Callable[[dict[str, Any]], str] | None = None,
        user_resolver: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ):
        self.app = app
        self.gateway = gateway
        self.tenant_resolver = tenant_resolver or (lambda scope: "default")
        self.user_resolver = user_resolver or (lambda scope: {"role": "anonymous"})

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            probe = GatewayRequest(
                tenant=self.tenant_resolver(scope),
                app="fastapi",
                user=self.user_resolver(scope),
                context={"task_type": "http_request", "risk": "low"},
                messages=[],
            )
            scope["policyaware.decision"] = self.gateway.policy_engine.decide(
                probe, self.gateway.data_protection.inspect("")
            )
        await self.app(scope, receive, send)

