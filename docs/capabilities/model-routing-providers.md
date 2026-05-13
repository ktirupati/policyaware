# Model Routing And Providers

## What It Does

Model routing selects a compliant model/provider after policy allows a request.

Routing can consider:

- provider
- region
- capability
- availability
- cost
- quality score
- risk tier

## Imports

```python
from policyaware import ModelCandidate, ModelRouter, ProviderRegistry, SimulatedProvider
```

## Main APIs

| API | Type | What It Does |
| --- | --- | --- |
| `ModelCandidate(...)` | model | Describes one routable model/provider option. |
| `ModelRouter(models=[...])` | class | Selects a compliant model for an allowed request. |
| `router.route(request, policy)` | method | Returns the selected route or fallback route. |
| `RouteDecision(...)` | model | Result object returned by the router. |
| `ProviderRegistry({...})` | class | Maps provider names to provider adapter instances. |
| Provider adapter classes | classes | Execute calls against local or external model platforms. |

## `ModelCandidate` Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | `str` | Logical model name used by PolicyAware. |
| `provider` | `str` | Provider key, such as `local`, `azure-openai`, `anthropic`, `ollama`, or `vllm`. |
| `capabilities` | `list[str]` | Supported capabilities: `text`, `embeddings`, `rerank`, or `tools`. |
| `region` | `str` | Region where the model is allowed or hosted. |
| `max_tokens` | `int` | Maximum token budget for the model. |
| `cost_per_1k_tokens` | `float` | Estimated cost used for routing and budget controls. |
| `quality_score` | `float` | Relative quality score used by the router. |
| `available` | `bool` | Whether the model is eligible for routing. |
| `metadata` | `dict` | Provider-specific configuration such as deployment or provider model name. |

## `RouteDecision` Result Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `model` | `ModelCandidate` | Selected model/provider candidate. |
| `fallback_used` | `bool` | True when routing had to use a fallback model. |
| `reason` | `str` | Human-readable routing reason. |

## Router Example

```python
from policyaware import GatewayRequest, ModelCandidate, ModelRouter, PolicyDecision
from policyaware.models import Decision, RiskTier

router = ModelRouter(
    models=[
        ModelCandidate(
            name="local/sim-small",
            provider="local",
            region="us",
            cost_per_1k_tokens=0.0,
            quality_score=0.7,
        ),
        ModelCandidate(
            name="approved/high-quality",
            provider="azure_openai",
            region="us",
            cost_per_1k_tokens=0.02,
            quality_score=0.95,
        ),
    ]
)

request = GatewayRequest(tenant="acme", app="demo", context={"region": "us"})
policy = PolicyDecision(
    decision=Decision.ALLOW,
    reason="Allowed",
    risk_score=0.2,
    risk_tier=RiskTier.LOW,
)

route = router.route(request, policy)
print(route.model.name)
print(route.reason)
```

## Provider Registry

```python
from policyaware import ProviderRegistry, SimulatedProvider

registry = ProviderRegistry({"local": SimulatedProvider()})
```

## Supported Adapter Classes

- `SimulatedProvider`
- `OpenAICompatibleProvider`
- `AzureOpenAIProvider`
- `AnthropicProvider`
- `BedrockProvider`
- `VertexAIProvider`
- `OllamaProvider`
- `VLLMProvider`

Use real provider adapters only when credentials and enterprise approval are available.

## Test Coverage Note

Provider adapter classes are covered structurally in local tests, but live calls to Azure OpenAI, Anthropic, Bedrock, Vertex AI, Ollama, and vLLM require real credentials or running endpoints.

PolicyAware can verify the routing and provider selection locally with `SimulatedProvider`. To verify external providers, run the live smoke tests below in an environment where credentials and endpoints are approved.

## Provider Names

Use these provider names in `ModelCandidate.provider`:

| Provider | Provider Name |
| --- | --- |
| Local simulated provider | `local` |
| OpenAI-compatible API | `openai-compatible` |
| Azure OpenAI | `azure-openai` |
| Anthropic | `anthropic` |
| Amazon Bedrock | `bedrock` |
| Google Vertex AI | `vertex-ai` |
| Ollama | `ollama` |
| vLLM | `vllm` |

## Common Policy For Provider Tests

Save as `provider-test-policy.yaml`.

```yaml
id: provider_test_policy
schema_version: "0.2"
default: deny

rules:
  - name: deny_secrets
    effect: deny
    when:
      data.contains_secrets: true

  - name: allow_low_medium_risk_provider_tests
    effect: allow
    when:
      user.role_in:
        - developer
        - platform_engineer
      request.region: us
      risk.tier_in:
        - low
        - medium
```

## Local Simulated Provider

Use this first. It requires no credentials.

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

## OpenAI-Compatible API

Use this for OpenAI-compatible chat-completions endpoints, including some self-hosted services.

Environment:

```bash
set POLICYAWARE_OPENAI_BASE_URL=https://your-openai-compatible-host/v1
set POLICYAWARE_OPENAI_API_KEY=your-key
```

Python:

```python
from policyaware import Gateway, GatewayRequest, ModelCandidate, ModelRouter, OpenAICompatibleProvider, ProviderRegistry

gateway = Gateway.from_policy_file("provider-test-policy.yaml")
gateway.router = ModelRouter(
    [
        ModelCandidate(
            name="gpt-compatible-model",
            provider="openai-compatible",
            region="us",
            metadata={"provider_model": "your-provider-model-name"},
        )
    ]
)
gateway.provider_registry = ProviderRegistry(
    {"openai-compatible": OpenAICompatibleProvider()}
)

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="provider-test",
        user={"id": "u1", "role": "developer"},
        context={"region": "us", "risk": "low", "task_type": "provider_test"},
        messages=[{"role": "user", "content": "Say hello."}],
    )
)

print(response.content)
```

## Azure OpenAI

Environment:

```bash
set POLICYAWARE_AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
set POLICYAWARE_AZURE_OPENAI_API_KEY=your-key
set POLICYAWARE_AZURE_OPENAI_API_VERSION=2024-06-01
```

Python:

```python
from policyaware import AzureOpenAIProvider, Gateway, GatewayRequest, ModelCandidate, ModelRouter, ProviderRegistry

gateway = Gateway.from_policy_file("provider-test-policy.yaml")
gateway.router = ModelRouter(
    [
        ModelCandidate(
            name="azure/gpt",
            provider="azure-openai",
            region="us",
            metadata={"deployment": "your-azure-deployment-name"},
        )
    ]
)
gateway.provider_registry = ProviderRegistry(
    {"azure-openai": AzureOpenAIProvider()}
)

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="azure-test",
        user={"id": "u1", "role": "developer"},
        context={"region": "us", "risk": "low", "max_output_tokens": 128},
        messages=[{"role": "user", "content": "Say hello from Azure OpenAI."}],
    )
)

print(response.content)
```

## Anthropic

Environment:

```bash
set POLICYAWARE_ANTHROPIC_API_KEY=your-key
```

Python:

```python
from policyaware import AnthropicProvider, Gateway, GatewayRequest, ModelCandidate, ModelRouter, ProviderRegistry

gateway = Gateway.from_policy_file("provider-test-policy.yaml")
gateway.router = ModelRouter(
    [
        ModelCandidate(
            name="anthropic/claude",
            provider="anthropic",
            region="us",
            metadata={"provider_model": "claude-3-5-sonnet-latest"},
        )
    ]
)
gateway.provider_registry = ProviderRegistry({"anthropic": AnthropicProvider()})

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="anthropic-test",
        user={"id": "u1", "role": "developer"},
        context={"region": "us", "risk": "low", "max_output_tokens": 128},
        messages=[{"role": "user", "content": "Say hello from Anthropic."}],
    )
)

print(response.content)
```

## Amazon Bedrock

Install:

```bash
pip install "policyaware[providers]"
```

Environment:

```bash
set AWS_REGION=us-east-1
```

Python:

```python
from policyaware import BedrockProvider, Gateway, GatewayRequest, ModelCandidate, ModelRouter, ProviderRegistry

gateway = Gateway.from_policy_file("provider-test-policy.yaml")
gateway.router = ModelRouter(
    [
        ModelCandidate(
            name="bedrock/claude",
            provider="bedrock",
            region="us",
            metadata={"provider_model": "anthropic.claude-3-5-sonnet-20240620-v1:0"},
        )
    ]
)
gateway.provider_registry = ProviderRegistry({"bedrock": BedrockProvider()})

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="bedrock-test",
        user={"id": "u1", "role": "developer"},
        context={"region": "us", "risk": "low", "max_output_tokens": 128},
        messages=[{"role": "user", "content": "Say hello from Bedrock."}],
    )
)

print(response.content)
```

## Google Vertex AI

Environment:

```bash
set POLICYAWARE_VERTEX_PROJECT=your-gcp-project
set POLICYAWARE_VERTEX_LOCATION=us-central1
set POLICYAWARE_VERTEX_ACCESS_TOKEN=your-oauth-token
```

Python:

```python
from policyaware import Gateway, GatewayRequest, ModelCandidate, ModelRouter, ProviderRegistry, VertexAIProvider

gateway = Gateway.from_policy_file("provider-test-policy.yaml")
gateway.router = ModelRouter(
    [
        ModelCandidate(
            name="gemini-1.5-flash",
            provider="vertex-ai",
            region="us",
            metadata={"provider_model": "gemini-1.5-flash"},
        )
    ]
)
gateway.provider_registry = ProviderRegistry({"vertex-ai": VertexAIProvider()})

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="vertex-test",
        user={"id": "u1", "role": "developer"},
        context={"region": "us", "risk": "low", "max_output_tokens": 128},
        messages=[{"role": "user", "content": "Say hello from Vertex AI."}],
    )
)

print(response.content)
```

## Ollama

Start Ollama locally and pull a model first:

```bash
ollama pull llama3.2
ollama serve
```

Python:

```python
from policyaware import Gateway, GatewayRequest, ModelCandidate, ModelRouter, OllamaProvider, ProviderRegistry

gateway = Gateway.from_policy_file("provider-test-policy.yaml")
gateway.router = ModelRouter(
    [
        ModelCandidate(
            name="llama3.2",
            provider="ollama",
            region="us",
            metadata={"provider_model": "llama3.2"},
        )
    ]
)
gateway.provider_registry = ProviderRegistry(
    {"ollama": OllamaProvider(base_url="http://localhost:11434")}
)

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="ollama-test",
        user={"id": "u1", "role": "developer"},
        context={"region": "us", "risk": "low"},
        messages=[{"role": "user", "content": "Say hello from Ollama."}],
    )
)

print(response.content)
```

## vLLM

Start a vLLM OpenAI-compatible server first.

Example server command:

```bash
python -m vllm.entrypoints.openai.api_server --model your-model --port 8000
```

Python:

```python
from policyaware import Gateway, GatewayRequest, ModelCandidate, ModelRouter, ProviderRegistry, VLLMProvider

gateway = Gateway.from_policy_file("provider-test-policy.yaml")
gateway.router = ModelRouter(
    [
        ModelCandidate(
            name="vllm/local",
            provider="vllm",
            region="us",
            metadata={"provider_model": "your-model"},
        )
    ]
)
gateway.provider_registry = ProviderRegistry(
    {"vllm": VLLMProvider(base_url="http://localhost:8000/v1")}
)

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="vllm-test",
        user={"id": "u1", "role": "developer"},
        context={"region": "us", "risk": "low"},
        messages=[{"role": "user", "content": "Say hello from vLLM."}],
    )
)

print(response.content)
```

## Sample Routing Configuration

The current `ModelRouter` is configured in Python. You can keep a YAML routing file in your app and load it into `ModelCandidate` objects.

Save as `routing.yaml`:

```yaml
models:
  - name: local/sim-small
    provider: local
    region: us
    capabilities: [text]
    cost_per_1k_tokens: 0.0
    quality_score: 0.7

  - name: azure/gpt-approved
    provider: azure-openai
    region: us
    capabilities: [text]
    cost_per_1k_tokens: 0.02
    quality_score: 0.95
    metadata:
      deployment: your-azure-deployment-name

  - name: ollama/llama3.2
    provider: ollama
    region: us
    capabilities: [text]
    cost_per_1k_tokens: 0.0
    quality_score: 0.75
    metadata:
      provider_model: llama3.2
```

Load it:

```python
import yaml
from policyaware import ModelCandidate, ModelRouter

with open("routing.yaml", "r", encoding="utf-8") as handle:
    config = yaml.safe_load(handle)

router = ModelRouter(
    [ModelCandidate(**item) for item in config["models"]]
)
```
