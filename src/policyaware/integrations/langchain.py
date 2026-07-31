from __future__ import annotations

from typing import Any

from policyaware.gateway import Gateway
from policyaware.integrations.callbacks import BasePolicyAwareCallbackHandler, PolicyAwareCallbackResult
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


class PolicyAwareCallbackHandler(BasePolicyAwareCallbackHandler):
    """LangChain-compatible callback handler without a hard LangChain dependency.

    Use this in LangChain pipelines as:
    `callbacks=[PolicyAwareCallbackHandler(config="policyaware.yaml")]`.
    """

    def __init__(self, *args: Any, **kwargs: Any):
        kwargs.setdefault("app", "langchain")
        super().__init__(*args, **kwargs)

    def on_llm_start(
        self,
        serialized: dict[str, Any] | None = None,
        prompts: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        self.start(prompts or kwargs.get("prompts") or serialized, langchain_serialized=serialized or {})

    async def aon_llm_start(
        self,
        serialized: dict[str, Any] | None = None,
        prompts: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        self.on_llm_start(serialized=serialized, prompts=prompts, **kwargs)

    def on_llm_new_token(self, token: str, **kwargs: Any) -> None:
        self.add_token(token)

    async def aon_llm_new_token(self, token: str, **kwargs: Any) -> None:
        self.on_llm_new_token(token, **kwargs)

    def on_llm_end(self, response: Any = None, **kwargs: Any) -> PolicyAwareCallbackResult:
        return self.finish(_extract_langchain_output(response), langchain_metadata=kwargs)

    async def aon_llm_end(self, response: Any = None, **kwargs: Any) -> PolicyAwareCallbackResult:
        return self.on_llm_end(response, **kwargs)

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        self.error(error)

    async def aon_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        self.on_llm_error(error, **kwargs)


def _extract_langchain_output(response: Any) -> Any:
    if response is None:
        return None
    generations = getattr(response, "generations", None)
    if generations is not None:
        return generations
    return response
