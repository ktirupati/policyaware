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
| Optional integrations | Installed only through extras such as `privacy`, `guardrails`, `providers`, `ml`, `onnx`, and `all` |

## Optional Extras

| Extra | Installs | Use When |
| --- | --- | --- |
| `policyaware[privacy]` | Presidio Analyzer, Presidio Anonymizer, spaCy | Stronger PII detection and redaction workflows |
| `policyaware[guardrails]` | NeMo Guardrails, Guardrails AI | Full-stack guardrail orchestration |
| `policyaware[providers]` | Provider helper dependencies such as `boto3` | Cloud provider adapters such as Bedrock |
| `policyaware[ml]` | Transformers and Torch | Optional ML classifiers and prompt-injection/domain signals |
| `policyaware[onnx]` | Transformers and ONNX runtime path dependencies | ONNX-friendly classifier execution |
| `policyaware[all]` | All optional stacks | Full local experimentation environment |

Backward-compatible aliases include `presidio`, `nemo`, `guardrails-ai`, and `full`.

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
| LlamaIndex wrapper | Lightweight wrapper available | `PolicyAwareLLM` can wrap gateway-style completion. |
| LlamaIndex callback | Available | RAG-oriented callback defaults include citation checks. |
| MCP/tool governance | Available | Use `ToolPolicyEngine` for connector/action permissions. |

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
