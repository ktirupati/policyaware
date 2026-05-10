from __future__ import annotations

from policyaware.gateway import Gateway
from policyaware.models import GatewayRequest


class PolicyAwareChatModel:
    """Small LangChain-compatible callable wrapper.

    This avoids a hard dependency on LangChain while offering the same basic call shape.
    """

    def __init__(self, gateway: Gateway, app: str = "langchain", tenant: str = "default"):
        self.gateway = gateway
        self.app = app
        self.tenant = tenant

    def invoke(self, prompt: str, **kwargs: object) -> str:
        response = self.gateway.chat(
            GatewayRequest(
                tenant=self.tenant,
                app=self.app,
                user=kwargs.get("user", {"role": "developer"}),  # type: ignore[arg-type]
                context=kwargs.get("context", {"task_type": "chain", "risk": "low"}),  # type: ignore[arg-type]
                messages=[{"role": "user", "content": prompt}],
            )
        )
        return response.content

