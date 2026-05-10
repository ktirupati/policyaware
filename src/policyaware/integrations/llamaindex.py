from __future__ import annotations

from policyaware.gateway import Gateway
from policyaware.models import GatewayRequest


class PolicyAwareLLM:
    """LlamaIndex-style completion wrapper without a hard dependency."""

    def __init__(self, gateway: Gateway, app: str = "llamaindex", tenant: str = "default"):
        self.gateway = gateway
        self.app = app
        self.tenant = tenant

    def complete(self, prompt: str) -> str:
        response = self.gateway.chat(
            GatewayRequest(
                tenant=self.tenant,
                app=self.app,
                user={"role": "developer"},
                context={"task_type": "rag_answer", "risk": "low", "require_citations": True},
                messages=[{"role": "user", "content": prompt}],
            )
        )
        return response.content

