from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from policyaware.gateway import Gateway
from policyaware.models import GatewayRequest, GatewayResponse
from policyaware.rejections import policy_rejection


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


def policyaware_json_response(response: GatewayResponse) -> Any:
    """Return a FastAPI/Starlette JSONResponse preserving PolicyAware denial fields.

    Use this helper inside application routes after ``gateway.chat(...)`` when a
    blocked or approval-gated request should be returned to the caller instead
    of invoking a model or tool.
    """

    rejection = policy_rejection(response)
    if not rejection:
        return None
    try:
        from fastapi.responses import JSONResponse
    except ImportError as exc:  # pragma: no cover - optional dependency branch
        raise RuntimeError("Install FastAPI to use policyaware_json_response.") from exc
    return JSONResponse(
        status_code=rejection.status_code,
        content={"error": "policyaware_rejection", "rejection": rejection.model_dump(mode="json")},
    )
