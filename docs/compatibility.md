# Compatibility And Integration Status

PolicyAware keeps the default install lightweight and makes heavier provider, privacy, guardrail, and ML dependencies optional.

## Runtime Compatibility

| Area | Status |
| --- | --- |
| Python | Python 3.10+ |
| Operating systems | Windows, macOS, Linux expected for core package |
| Base install | `pip install policyaware` |
| Base dependencies | `pydantic`, `PyYAML`, `typer`, `rich` |
| Local execution | No network calls required for core policy, scan, data protection, routing abstractions, eval, and audit features |
| HTTP sidecar | Standard-library local HTTP service for non-Python applications |
| Optional integrations | Installed only through extras such as `privacy`, `guardrails`, `providers`, `azure`, `gcp`, `ml`, `onnx`, and `all` |

## Optional Extras

| Extra | Installs | Use When |
| --- | --- | --- |
| `policyaware[privacy]` | Presidio Analyzer, Presidio Anonymizer, spaCy | Stronger PII detection and redaction workflows |
| `policyaware[guardrails]` | NeMo Guardrails, Guardrails AI | Full-stack guardrail orchestration |
| `policyaware[haystack]` | Haystack AI | Haystack RAG and agent integration environment |
| `policyaware[providers]` | Provider helper dependencies such as `boto3` | Cloud provider adapters such as Bedrock and S3 dynamic policy distribution |
| `policyaware[azure]` | Azure Identity and Azure Storage File Data Lake | ADLS Gen2 dynamic policy distribution through `abfs://` or `abfss://` paths |
| `policyaware[gcp]` | Google Cloud Storage | GCS dynamic policy distribution through `gs://` paths |
| `policyaware[ml]` | Transformers and Torch | Optional ML classifiers and prompt-injection/domain signals |
| `policyaware[onnx]` | Transformers and ONNX runtime path dependencies | ONNX-friendly classifier execution |
| `policyaware[all]` | All optional stacks | Full local experimentation environment |

Backward-compatible aliases include `presidio`, `nemo`, `guardrails-ai`, and `full`.

## Dependency Footprint Guidance

The default install is intentionally small:

```bash
pip install policyaware
```

Use the base package when you need deterministic governance features such as:

- RBAC and context-aware policy checks
- explicit prompt filtering
- PII/PHI/secrets pattern detection
- MCP/tool permission checks
- model routing abstractions
- token and cost controls
- audit traces
- `policyaware scan` for offline repository checks

Install optional extras only when the use case requires them:

| Need | Recommended Install | Footprint Note |
| --- | --- | --- |
| Basic policy, scan, routing, audit, and tool governance | `pip install policyaware` | Smallest runtime footprint. |
| Stronger PII detection and anonymization | `pip install "policyaware[privacy]"` | Adds Presidio and spaCy, which increase image size. |
| Prompt-injection or semantic ML signals | `pip install "policyaware[ml]"` | Adds Transformers and Torch, usually the heaviest local dependency path. |
| ONNX-friendly classifier execution | `pip install "policyaware[onnx]"` | Adds ONNX runtime tooling; still heavier than base. |
| NeMo Guardrails or Guardrails AI orchestration | `pip install "policyaware[guardrails]"` | Adds guardrail framework dependencies and their transitive packages. |
| Full experimentation environment | `pip install "policyaware[all]"` | Convenient for demos and labs, but not recommended as the default production image. |

For production containers, prefer installing only the extras required by that service. For example, a CI scanner image may only need `policyaware`, a privacy-heavy support copilot may need `policyaware[privacy]`, and an agent safety evaluation service may need `policyaware[ml]` or `policyaware[guardrails]`.

This split is intentional: PolicyAware keeps everyday policy enforcement fast and clean, while deeper semantic anonymization or ML safety checks remain opt-in.

## Provider Adapter Status

| Provider Adapter | Status | Notes |
| --- | --- | --- |
| `SimulatedProvider` | Local tested | Default local provider for examples and tests. |
| `OpenAICompatibleProvider` | Structural adapter | Use for OpenAI-compatible endpoints when configured with base URL and credentials. |
| `AzureOpenAIProvider` | Structural adapter | Requires Azure endpoint, deployment/model name, API key, and API version. |
| `AnthropicProvider` | Structural adapter | Requires Anthropic API key and model name. |
| `BedrockProvider` | Structural adapter | Requires AWS credentials, region, model ID, and `boto3` extra. |
| `VertexAIProvider` | Structural adapter | Requires Google Cloud project, region, model, and auth setup. |
| `OllamaProvider` | Structural adapter | Requires a running Ollama endpoint and local model. |
| `VLLMProvider` | Structural adapter | Requires a running vLLM/OpenAI-compatible endpoint. |

Structural adapter means the class exists and follows the PolicyAware provider interface. Live calls depend on credentials, endpoints, quotas, cloud permissions, and model availability in the user's environment.

## Framework Integration Status

| Integration | Status | Notes |
| --- | --- | --- |
| FastAPI middleware | Shim/example available | Use to protect API routes before model execution. |
| Flask middleware | Shim/example available | Use to protect Flask routes. |
| LangChain wrapper | Lightweight wrapper available | `PolicyAwareChatModel` can wrap gateway-style usage. |
| LangChain callback | Available | Aggregates streamed tokens and stores `PolicyAwareCallbackResult`. |
| LangGraph node guard | Available | Dependency-free `PolicyAwareNodeGuard` wraps graph nodes and checks tool calls without requiring LangGraph at import time. |
| LlamaIndex wrapper | Lightweight wrapper available | `PolicyAwareLLM` can wrap gateway-style completion. |
| LlamaIndex callback | Available | RAG-oriented callback defaults include citation checks. |
| Haystack-style components | Available | Query governance, output evaluation, and tool-governance components expose `run(...)` methods without requiring Haystack at import time. |
| Microsoft AGT-style evidence export | Available | Dependency-free JSON mapping helpers for policy, tool, gateway, and audit decisions. |
| MCP/tool governance | Available | Use `ToolPolicyEngine` for connector/action permissions. |
| HTTP sidecar gateway | Available | `policyaware up` exposes local HTTP endpoints for non-Python services. |

## Scan Coverage

| File Type / Area | Status |
| --- | --- |
| Python, JavaScript, TypeScript, Java, Scala, Go, Rust, shell | Supported as text/code scan inputs |
| YAML, JSON, TOML, INI, properties, env files | Supported |
| Jupyter notebooks | Supported through notebook text extraction |
| SQL, Terraform, Dockerfile, Markdown, text | Supported |
| Binary files | Skipped |
| Large files | Skipped by default based on configured max size |
| ML model files | Not loaded or executed |

## Testing Status

Core local tests cover policy decisions, scanner behavior, CLI behavior, packaging metadata, provider abstractions, guardrail adapter contracts, and callback integrations.

Live provider calls are intentionally not run in the default test suite because they require external credentials and cloud resources.

## Official Vs Compatible

PolicyAware integrates with, adapts to, or exports data for multiple ecosystems. Unless explicitly stated, external project names do not imply affiliation, endorsement, or official support from those projects.

See [Integration Strategy](integrations-strategy.md) for wording and adoption guidance.
