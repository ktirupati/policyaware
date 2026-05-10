from __future__ import annotations

from typing import Any

from policyaware.gateway import Gateway
from policyaware.models import GatewayRequest


def before_request_probe(gateway: Gateway, tenant: str, user: dict[str, Any]) -> Any:
    """Create a Flask before_request hook for lightweight policy probing."""

    def hook() -> None:
        try:
            from flask import g
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Install flask to use the Flask integration.") from exc

        probe = GatewayRequest(
            tenant=tenant,
            app="flask",
            user=user,
            context={"task_type": "http_request", "risk": "low"},
        )
        g.policyaware_decision = gateway.policy_engine.decide(
            probe, gateway.data_protection.inspect("")
        )

    return hook

