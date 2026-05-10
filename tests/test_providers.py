from policyaware.models import GatewayRequest, ModelCandidate
from policyaware.providers import (
    AnthropicProvider,
    AzureOpenAIProvider,
    BedrockProvider,
    OllamaProvider,
    VLLMProvider,
    VertexAIProvider,
    default_provider_registry,
)


def request() -> GatewayRequest:
    return GatewayRequest(
        tenant="acme",
        app="test",
        user={"role": "developer"},
        context={"temperature": 0.2, "max_output_tokens": 128, "top_p": 0.9},
        messages=[
            {"role": "system", "content": "Be concise."},
            {"role": "user", "content": "Hello"},
        ],
    )


def model(provider: str = "local") -> ModelCandidate:
    return ModelCandidate(name="provider-model", provider=provider)


def test_azure_openai_payload_excludes_model_for_deployment_route() -> None:
    provider = AzureOpenAIProvider(endpoint="https://example.openai.azure.com", api_key="key")

    payload = provider._chat_payload(request(), model("azure-openai"), include_model=False)

    assert "model" not in payload
    assert payload["messages"][1]["content"] == "Hello"
    assert payload["max_tokens"] == 128


def test_anthropic_splits_system_prompt_from_messages() -> None:
    provider = AnthropicProvider(api_key="key")

    assert provider._system_prompt(request()) == "Be concise."
    assert provider._messages(request()) == [{"role": "user", "content": "Hello"}]


def test_bedrock_maps_messages_and_inference_config() -> None:
    provider = BedrockProvider(client=object())

    messages = provider._messages(request())
    config = provider._inference_config(request())

    assert messages == [{"role": "user", "content": [{"text": "Hello"}]}]
    assert config == {"maxTokens": 128, "temperature": 0.2, "topP": 0.9}


def test_vertex_maps_contents_and_generation_config() -> None:
    provider = VertexAIProvider(project="p", access_token="token")

    contents = provider._contents(request())
    config = provider._generation_config(request())

    assert contents == [{"role": "user", "parts": [{"text": "Hello"}]}]
    assert config == {"maxOutputTokens": 128, "temperature": 0.2, "topP": 0.9}


def test_ollama_requires_no_api_key() -> None:
    provider = OllamaProvider(base_url="http://localhost:11434")

    assert provider.base_url == "http://localhost:11434"


def test_vllm_defaults_to_local_openai_compatible_server() -> None:
    provider = VLLMProvider()

    assert provider.base_url.endswith("/v1")


def test_default_registry_contains_provider_adapters() -> None:
    registry = default_provider_registry()

    for provider_name in [
        "openai-compatible",
        "azure-openai",
        "anthropic",
        "bedrock",
        "vertex-ai",
        "ollama",
        "vllm",
    ]:
        assert provider_name in registry.providers

