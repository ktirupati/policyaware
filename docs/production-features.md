# Production Feature Additions

This document summarizes the next production-oriented modules added to PolicyAware.

## Provider Adapters

PolicyAware includes provider adapters for common hosted and local model platforms:

- `OpenAICompatibleProvider`
- `AzureOpenAIProvider`
- `AnthropicProvider`
- `BedrockProvider`
- `VertexAIProvider`
- `OllamaProvider`
- `VLLMProvider`

```python
from policyaware import Gateway, OpenAICompatibleProvider, ProviderRegistry

provider = OpenAICompatibleProvider(
    base_url="https://api.example.com/v1",
    api_key="YOUR_TOKEN",
)
registry = ProviderRegistry({"openai-compatible": provider})

gateway = Gateway.from_policy_file("examples/policies/basic.yaml")
gateway.provider_registry = registry
```

The default simulated provider still works without API keys.

### Provider Environment Variables

```text
POLICYAWARE_OPENAI_BASE_URL
POLICYAWARE_OPENAI_API_KEY
POLICYAWARE_AZURE_OPENAI_ENDPOINT
POLICYAWARE_AZURE_OPENAI_API_KEY
POLICYAWARE_AZURE_OPENAI_API_VERSION
POLICYAWARE_ANTHROPIC_API_KEY
POLICYAWARE_VERTEX_PROJECT
POLICYAWARE_VERTEX_LOCATION
POLICYAWARE_VERTEX_ACCESS_TOKEN
POLICYAWARE_OLLAMA_BASE_URL
POLICYAWARE_VLLM_BASE_URL
POLICYAWARE_VLLM_API_KEY
AWS_REGION
AWS_DEFAULT_REGION
```

Bedrock uses optional `boto3`; install it separately or pass a preconfigured Bedrock Runtime client.

### Multi-Provider Registry

See `examples/providers/provider-routing.py` for a router and provider registry that includes Azure OpenAI, Anthropic, Bedrock, Vertex AI, Ollama, and vLLM.

## Persistent Audit Storage

Use SQLite audit storage when local JSONL is not enough:

```python
from policyaware.audit import SQLiteAuditLogger

gateway.audit_logger = SQLiteAuditLogger(".policyaware/audit.db")
```

Generate a static trace viewer:

```bash
policyaware audit view-sqlite --db .policyaware/audit.db --out .policyaware/trace-viewer.html
```

## Observability Exporters

Prometheus text exposition:

```bash
policyaware observability prometheus --traces-file .policyaware/traces.jsonl --out .policyaware/metrics.prom
```

OpenTelemetry-shaped JSON spans:

```bash
policyaware observability otel-json --traces-file .policyaware/traces.jsonl --out .policyaware/otel-spans.json
```

## Approval Integrations

File-backed approval queue:

```python
from policyaware.approvals import FileApprovalClient

gateway.approval_client = FileApprovalClient(".policyaware/approvals.jsonl")
```

Webhook approval hook:

```python
from policyaware.approvals import WebhookApprovalClient

gateway.approval_client = WebhookApprovalClient("https://workflow.example.com/ai-approval")
```

When policy returns `require_approval`, the gateway creates an approval request and does not execute the model.

## Executable Golden Dataset Evals

Parse only:

```bash
policyaware eval run examples/evals/executable_governance_cases.yaml
```

Execute cases through a policy:

```bash
policyaware eval run examples/evals/executable_governance_cases.yaml --policy-file examples/policies/basic.yaml
```

Executable cases compare actual decisions and reason codes with expected governance outcomes.

## Policy Schema Validation

Validate a policy before using it:

```bash
policyaware policy validate examples/policies/basic.yaml
```

Invalid policies return clear errors:

```bash
policyaware policy validate examples/policies/invalid-policy.yaml
```

Validation catches:

- unknown top-level fields
- invalid `default`
- missing rule names
- duplicate rule names
- invalid `effect`
- invalid transform `action`
- invalid condition roots
- `_in` / `_not_in` values that are not lists
- `_lte` / `_gte` values that are not numeric
