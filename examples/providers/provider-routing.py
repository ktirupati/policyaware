from policyaware import (
    AnthropicProvider,
    AzureOpenAIProvider,
    BedrockProvider,
    Gateway,
    ModelCandidate,
    OllamaProvider,
    ProviderRegistry,
    VLLMProvider,
    VertexAIProvider,
)
from policyaware.routing import ModelRouter


registry = ProviderRegistry(
    {
        "azure-openai": AzureOpenAIProvider(),
        "anthropic": AnthropicProvider(),
        "bedrock": BedrockProvider(),
        "vertex-ai": VertexAIProvider(),
        "ollama": OllamaProvider(),
        "vllm": VLLMProvider(),
    }
)

router = ModelRouter(
    [
        ModelCandidate(
            name="gpt-4.1-mini",
            provider="azure-openai",
            metadata={"deployment": "gpt-4-1-mini"},
            quality_score=0.9,
        ),
        ModelCandidate(
            name="claude-sonnet",
            provider="anthropic",
            metadata={"provider_model": "claude-sonnet-4-5-20250929"},
            quality_score=0.92,
        ),
        ModelCandidate(
            name="anthropic.claude-3-5-sonnet",
            provider="bedrock",
            metadata={"provider_model": "anthropic.claude-3-5-sonnet-20240620-v1:0"},
            quality_score=0.9,
        ),
        ModelCandidate(
            name="gemini-2.0-flash",
            provider="vertex-ai",
            quality_score=0.9,
        ),
        ModelCandidate(
            name="llama3.1",
            provider="ollama",
            cost_per_1k_tokens=0,
        ),
        ModelCandidate(
            name="NousResearch/Meta-Llama-3-8B-Instruct",
            provider="vllm",
            cost_per_1k_tokens=0,
        ),
    ]
)

gateway = Gateway.from_policy_file("examples/policies/basic.yaml")
gateway.provider_registry = registry
gateway.router = router

