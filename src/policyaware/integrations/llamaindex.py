from __future__ import annotations

from typing import Any

from policyaware.gateway import Gateway
from policyaware.integrations.callbacks import BasePolicyAwareCallbackHandler, PolicyAwareCallbackResult
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


class PolicyAwareCallbackHandler(BasePolicyAwareCallbackHandler):
    """LlamaIndex-compatible callback handler without a hard LlamaIndex dependency.

    Use this around LlamaIndex events to aggregate streamed tokens and review
    generated output with PolicyAware.
    """

    def __init__(self, *args: Any, **kwargs: Any):
        kwargs.setdefault("app", "llamaindex")
        kwargs.setdefault(
            "context",
            {"region": "us", "task_type": "rag_answer", "risk": "low", "require_citations": True},
        )
        super().__init__(*args, **kwargs)

    def on_event_start(
        self,
        event_type: Any = None,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        payload = payload or {}
        prompt = (
            payload.get("prompt")
            or payload.get("messages")
            or payload.get("query")
            or payload.get("query_str")
            or kwargs.get("prompt")
        )
        self.start(prompt, llamaindex_event_type=str(event_type or ""), llamaindex_payload=payload)

    async def aon_event_start(
        self,
        event_type: Any = None,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self.on_event_start(event_type=event_type, payload=payload, **kwargs)

    def on_llm_new_token(self, token: str, **kwargs: Any) -> None:
        self.add_token(token)

    async def aon_llm_new_token(self, token: str, **kwargs: Any) -> None:
        self.on_llm_new_token(token, **kwargs)

    def on_event_end(
        self,
        event_type: Any = None,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> PolicyAwareCallbackResult:
        payload = payload or {}
        output = (
            payload.get("response")
            or payload.get("output")
            or payload.get("completion")
            or payload.get("text")
            or kwargs.get("response")
        )
        return self.finish(
            output,
            llamaindex_event_type=str(event_type or ""),
            llamaindex_end_payload=payload,
        )

    async def aon_event_end(
        self,
        event_type: Any = None,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> PolicyAwareCallbackResult:
        return self.on_event_end(event_type=event_type, payload=payload, **kwargs)

    def on_event_error(self, error: BaseException, **kwargs: Any) -> None:
        self.error(error)

    async def aon_event_error(self, error: BaseException, **kwargs: Any) -> None:
        self.on_event_error(error, **kwargs)
