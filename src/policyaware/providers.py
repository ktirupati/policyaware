from __future__ import annotations

from abc import ABC, abstractmethod
import json
import os
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError, URLError

from policyaware.models import GatewayRequest, ModelCandidate


class ModelProvider(ABC):
    @abstractmethod
    def generate(self, request: GatewayRequest, model: ModelCandidate) -> str:
        raise NotImplementedError


class SimulatedProvider(ModelProvider):
    """Local deterministic provider for development, tests, and policy simulation."""

    def generate(self, request: GatewayRequest, model: ModelCandidate) -> str:
        prompt = request.prompt_text.strip()
        task_type = request.context.get("task_type", "general")
        if not prompt:
            return f"[{model.name}] No prompt content supplied."
        return f"[{model.name}] {task_type} response: {prompt[:240]}"


class OpenAICompatibleProvider(ModelProvider):
    """Provider adapter for OpenAI-compatible chat completion APIs.

    This intentionally uses the Python standard library so the core package stays light. It works
    with hosted and self-hosted endpoints that support ``/chat/completions`` style APIs.
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout_seconds: int = 60,
        extra_headers: dict[str, str] | None = None,
    ):
        self.base_url = (base_url or os.getenv("POLICYAWARE_OPENAI_BASE_URL") or "").rstrip("/")
        self.api_key = api_key or os.getenv("POLICYAWARE_OPENAI_API_KEY")
        self.timeout_seconds = timeout_seconds
        self.extra_headers = extra_headers or {}

    def generate(self, request: GatewayRequest, model: ModelCandidate) -> str:
        if not self.base_url:
            raise RuntimeError("OpenAI-compatible provider requires a base_url.")

        payload: dict[str, Any] = {
            "model": model.metadata.get("provider_model", model.name),
            "messages": request.messages,
        }
        if "temperature" in request.context:
            payload["temperature"] = request.context["temperature"]
        if "max_output_tokens" in request.context:
            payload["max_tokens"] = request.context["max_output_tokens"]

        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", **self.extra_headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        endpoint = f"{self.base_url}/chat/completions"
        req = urlrequest.Request(endpoint, data=body, headers=headers, method="POST")
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Provider request failed with HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"Provider request failed: {exc}") from exc

        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"Provider response did not match chat completion schema: {data}") from exc


class AzureOpenAIProvider(OpenAICompatibleProvider):
    """Azure OpenAI chat-completions adapter.

    Expects an Azure endpoint such as ``https://my-resource.openai.azure.com`` and a deployment
    name in ``model.metadata["deployment"]`` or ``model.metadata["provider_model"]``.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        api_key: str | None = None,
        api_version: str | None = None,
        timeout_seconds: int = 60,
    ):
        super().__init__(base_url="", api_key=api_key, timeout_seconds=timeout_seconds)
        self.endpoint = (endpoint or os.getenv("POLICYAWARE_AZURE_OPENAI_ENDPOINT") or "").rstrip("/")
        self.api_key = api_key or os.getenv("POLICYAWARE_AZURE_OPENAI_API_KEY")
        self.api_version = api_version or os.getenv("POLICYAWARE_AZURE_OPENAI_API_VERSION", "2024-06-01")

    def generate(self, request: GatewayRequest, model: ModelCandidate) -> str:
        if not self.endpoint:
            raise RuntimeError("Azure OpenAI provider requires an endpoint.")
        if not self.api_key:
            raise RuntimeError("Azure OpenAI provider requires an api_key.")

        deployment = model.metadata.get("deployment") or model.metadata.get("provider_model") or model.name
        endpoint = (
            f"{self.endpoint}/openai/deployments/{deployment}/chat/completions"
            f"?api-version={self.api_version}"
        )
        payload = self._chat_payload(request, model, include_model=False)
        data = self._post_json(endpoint, payload, {"api-key": self.api_key})
        return self._extract_openai_text(data)

    def _chat_payload(
        self, request: GatewayRequest, model: ModelCandidate, include_model: bool = True
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"messages": request.messages}
        if include_model:
            payload["model"] = model.metadata.get("provider_model", model.name)
        if "temperature" in request.context:
            payload["temperature"] = request.context["temperature"]
        if "max_output_tokens" in request.context:
            payload["max_tokens"] = request.context["max_output_tokens"]
        return payload

    def _post_json(
        self, endpoint: str, payload: dict[str, Any], headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req_headers = {"Content-Type": "application/json", **(headers or {})}
        req = urlrequest.Request(endpoint, data=body, headers=req_headers, method="POST")
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Provider request failed with HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"Provider request failed: {exc}") from exc

    def _extract_openai_text(self, data: dict[str, Any]) -> str:
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"Provider response did not match chat completion schema: {data}") from exc


class AnthropicProvider(ModelProvider):
    """Anthropic Messages API adapter."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        anthropic_version: str = "2023-06-01",
        timeout_seconds: int = 60,
    ):
        self.api_key = api_key or os.getenv("POLICYAWARE_ANTHROPIC_API_KEY")
        self.base_url = (base_url or os.getenv("POLICYAWARE_ANTHROPIC_BASE_URL") or "https://api.anthropic.com").rstrip("/")
        self.anthropic_version = anthropic_version
        self.timeout_seconds = timeout_seconds

    def generate(self, request: GatewayRequest, model: ModelCandidate) -> str:
        if not self.api_key:
            raise RuntimeError("Anthropic provider requires an api_key.")
        payload: dict[str, Any] = {
            "model": model.metadata.get("provider_model", model.name),
            "max_tokens": request.context.get("max_output_tokens", 1024),
            "messages": self._messages(request),
        }
        system = self._system_prompt(request)
        if system:
            payload["system"] = system
        if "temperature" in request.context:
            payload["temperature"] = request.context["temperature"]

        data = self._post_json(
            f"{self.base_url}/v1/messages",
            payload,
            {
                "x-api-key": self.api_key,
                "anthropic-version": self.anthropic_version,
            },
        )
        try:
            return "".join(part.get("text", "") for part in data["content"] if part.get("type") == "text")
        except (KeyError, TypeError) as exc:
            raise RuntimeError(f"Anthropic response did not match Messages schema: {data}") from exc

    def _messages(self, request: GatewayRequest) -> list[dict[str, str]]:
        return [
            {"role": message.get("role", "user"), "content": message.get("content", "")}
            for message in request.messages
            if message.get("role") != "system"
        ]

    def _system_prompt(self, request: GatewayRequest) -> str | None:
        parts = [message.get("content", "") for message in request.messages if message.get("role") == "system"]
        return "\n".join(part for part in parts if part) or None

    def _post_json(
        self, endpoint: str, payload: dict[str, Any], headers: dict[str, str]
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req_headers = {"Content-Type": "application/json", **headers}
        req = urlrequest.Request(endpoint, data=body, headers=req_headers, method="POST")
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Anthropic request failed with HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"Anthropic request failed: {exc}") from exc


class BedrockProvider(ModelProvider):
    """Amazon Bedrock Converse adapter using optional boto3."""

    def __init__(self, region_name: str | None = None, client: Any | None = None):
        self.region_name = region_name or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        self.client = client

    def generate(self, request: GatewayRequest, model: ModelCandidate) -> str:
        client = self.client or self._client()
        response = client.converse(
            modelId=model.metadata.get("provider_model", model.name),
            messages=self._messages(request),
            inferenceConfig=self._inference_config(request),
        )
        try:
            return "".join(
                block.get("text", "")
                for block in response["output"]["message"]["content"]
                if "text" in block
            )
        except (KeyError, TypeError) as exc:
            raise RuntimeError(f"Bedrock response did not match Converse schema: {response}") from exc

    def _client(self) -> Any:
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "BedrockProvider requires boto3. Install with `pip install boto3` or pass a client."
            ) from exc
        return boto3.client("bedrock-runtime", region_name=self.region_name)

    def _messages(self, request: GatewayRequest) -> list[dict[str, Any]]:
        messages = []
        for message in request.messages:
            role = message.get("role", "user")
            if role == "system":
                continue
            messages.append({"role": role, "content": [{"text": message.get("content", "")}]})
        return messages

    def _inference_config(self, request: GatewayRequest) -> dict[str, Any]:
        config: dict[str, Any] = {}
        if "max_output_tokens" in request.context:
            config["maxTokens"] = request.context["max_output_tokens"]
        if "temperature" in request.context:
            config["temperature"] = request.context["temperature"]
        if "top_p" in request.context:
            config["topP"] = request.context["top_p"]
        return config


class VertexAIProvider(ModelProvider):
    """Vertex AI Gemini generateContent REST adapter.

    Requires a Google OAuth bearer token. In production this is usually supplied by an
    identity flow outside PolicyAware and passed as ``access_token``.
    """

    def __init__(
        self,
        project: str | None = None,
        location: str | None = None,
        access_token: str | None = None,
        api_version: str = "v1",
        timeout_seconds: int = 60,
    ):
        self.project = project or os.getenv("POLICYAWARE_VERTEX_PROJECT")
        self.location = location or os.getenv("POLICYAWARE_VERTEX_LOCATION", "us-central1")
        self.access_token = access_token or os.getenv("POLICYAWARE_VERTEX_ACCESS_TOKEN")
        self.api_version = api_version
        self.timeout_seconds = timeout_seconds

    def generate(self, request: GatewayRequest, model: ModelCandidate) -> str:
        if not self.project:
            raise RuntimeError("Vertex AI provider requires a project.")
        if not self.access_token:
            raise RuntimeError("Vertex AI provider requires an access_token.")
        model_name = model.metadata.get("provider_model", model.name)
        full_model = (
            model_name
            if model_name.startswith("projects/")
            else f"projects/{self.project}/locations/{self.location}/publishers/google/models/{model_name}"
        )
        endpoint = f"https://aiplatform.googleapis.com/{self.api_version}/{full_model}:generateContent"
        payload = {
            "contents": self._contents(request),
            "generationConfig": self._generation_config(request),
        }
        system = self._system_instruction(request)
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        data = self._post_json(endpoint, payload, {"Authorization": f"Bearer {self.access_token}"})
        try:
            return "".join(
                part.get("text", "")
                for candidate in data.get("candidates", [])
                for part in candidate.get("content", {}).get("parts", [])
                if "text" in part
            )
        except (KeyError, TypeError) as exc:
            raise RuntimeError(f"Vertex AI response did not match generateContent schema: {data}") from exc

    def _contents(self, request: GatewayRequest) -> list[dict[str, Any]]:
        contents = []
        for message in request.messages:
            role = message.get("role", "user")
            if role == "system":
                continue
            contents.append(
                {
                    "role": "model" if role == "assistant" else "user",
                    "parts": [{"text": message.get("content", "")}],
                }
            )
        return contents

    def _system_instruction(self, request: GatewayRequest) -> str | None:
        parts = [message.get("content", "") for message in request.messages if message.get("role") == "system"]
        return "\n".join(part for part in parts if part) or None

    def _generation_config(self, request: GatewayRequest) -> dict[str, Any]:
        config: dict[str, Any] = {}
        if "max_output_tokens" in request.context:
            config["maxOutputTokens"] = request.context["max_output_tokens"]
        if "temperature" in request.context:
            config["temperature"] = request.context["temperature"]
        if "top_p" in request.context:
            config["topP"] = request.context["top_p"]
        return config

    def _post_json(
        self, endpoint: str, payload: dict[str, Any], headers: dict[str, str]
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req_headers = {"Content-Type": "application/json", **headers}
        req = urlrequest.Request(endpoint, data=body, headers=req_headers, method="POST")
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Vertex AI request failed with HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"Vertex AI request failed: {exc}") from exc


class OllamaProvider(ModelProvider):
    """Ollama /api/chat adapter."""

    def __init__(self, base_url: str | None = None, timeout_seconds: int = 120):
        self.base_url = (base_url or os.getenv("POLICYAWARE_OLLAMA_BASE_URL") or "http://localhost:11434").rstrip("/")
        self.timeout_seconds = timeout_seconds

    def generate(self, request: GatewayRequest, model: ModelCandidate) -> str:
        payload: dict[str, Any] = {
            "model": model.metadata.get("provider_model", model.name),
            "messages": request.messages,
            "stream": False,
        }
        if "ollama_options" in request.context:
            payload["options"] = request.context["ollama_options"]
        data = self._post_json(f"{self.base_url}/api/chat", payload)
        try:
            return data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise RuntimeError(f"Ollama response did not match chat schema: {data}") from exc

    def _post_json(self, endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req = urlrequest.Request(
            endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlrequest.urlopen(req, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama request failed with HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc


class VLLMProvider(OpenAICompatibleProvider):
    """vLLM OpenAI-compatible server adapter."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout_seconds: int = 120,
    ):
        super().__init__(
            base_url=base_url or os.getenv("POLICYAWARE_VLLM_BASE_URL", "http://localhost:8000/v1"),
            api_key=api_key or os.getenv("POLICYAWARE_VLLM_API_KEY", "token-abc123"),
            timeout_seconds=timeout_seconds,
        )


class ProviderRegistry:
    def __init__(self, providers: dict[str, ModelProvider] | None = None):
        self.providers = providers or {"local": SimulatedProvider()}

    def register(self, name: str, provider: ModelProvider) -> None:
        self.providers[name] = provider

    def for_model(self, model: ModelCandidate) -> ModelProvider:
        return self.providers.get(model.provider, self.providers["local"])


def default_provider_registry() -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register("openai-compatible", OpenAICompatibleProvider())
    registry.register("azure-openai", AzureOpenAIProvider())
    registry.register("anthropic", AnthropicProvider())
    registry.register("bedrock", BedrockProvider())
    registry.register("vertex-ai", VertexAIProvider())
    registry.register("ollama", OllamaProvider())
    registry.register("vllm", VLLMProvider())
    return registry
