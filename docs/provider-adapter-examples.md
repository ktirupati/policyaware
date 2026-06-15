# Provider Adapter Examples

This page is a convenient root-level copy of the provider adapter guide.

See the full capability guide:

[Model Routing And Providers](capabilities/model-routing-providers.md)

## Quick Start

Use the local simulated provider first. It requires no credentials.

```python
from policyaware import Gateway, GatewayRequest, ModelCandidate, ModelRouter, ProviderRegistry, SimulatedProvider

gateway = Gateway.from_policy_file("provider-test-policy.yaml")
gateway.router = ModelRouter(
    [
        ModelCandidate(
            name="local/sim-small",
            provider="local",
            region="us",
            cost_per_1k_tokens=0.0,
        )
    ]
)
gateway.provider_registry = ProviderRegistry({"local": SimulatedProvider()})

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="provider-test",
        user={"id": "u1", "role": "developer"},
        context={"region": "us", "risk": "low", "task_type": "provider_test"},
        messages=[{"role": "user", "content": "Say hello from the local provider."}],
    )
)

print(response.route.model.provider)
print(response.content)
```

## Live Provider Note

Provider adapter classes are covered structurally in local tests, but live calls to Azure OpenAI, Anthropic, Bedrock, Vertex AI, Ollama, and vLLM require real credentials or running endpoints.

Use the full guide for:

- Azure OpenAI setup
- Anthropic setup
- Bedrock setup
- Vertex AI setup
- Ollama setup
- vLLM setup
- sample `routing.yaml`

## Credential Quick Reference

| Provider | Required Setup |
| --- | --- |
| Azure OpenAI | `POLICYAWARE_AZURE_OPENAI_ENDPOINT`, `POLICYAWARE_AZURE_OPENAI_API_KEY`, optional `POLICYAWARE_AZURE_OPENAI_API_VERSION` |
| Anthropic | `POLICYAWARE_ANTHROPIC_API_KEY` |
| Amazon Bedrock | AWS credentials from your environment plus `AWS_REGION`; install `policyaware[providers]` |
| Google Vertex AI | `POLICYAWARE_VERTEX_PROJECT`, `POLICYAWARE_VERTEX_LOCATION`, `POLICYAWARE_VERTEX_ACCESS_TOKEN` |
| Ollama | Running local Ollama service, usually `http://localhost:11434` |
| vLLM | Running OpenAI-compatible vLLM server, usually `http://localhost:8000/v1` |

Keep production credentials in your secret manager or runtime environment. Do not store provider keys in YAML policy files.
