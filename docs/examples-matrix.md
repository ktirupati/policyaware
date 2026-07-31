# Examples Matrix

Use this table to pick the fastest PolicyAware example for your use case.

| Use Case | Folder Or Doc | Command | What It Proves |
| --- | --- | --- | --- |
| FastAPI LLM policy middleware | `examples/fastapi-llm-policy-middleware` | `python app.py` | Protect an API endpoint before an LLM request reaches a provider. |
| LangChain policy guardrails | `examples/langchain-policy-guardrails` | `python chain_demo.py` | Apply PolicyAware decisions around chain-style LLM calls. |
| LangChain/LlamaIndex callbacks | `docs/capabilities/integration-callbacks.md` | Copy the callback sample | Capture streamed tokens, policy result, output leakage, evals, and token counts. |
| MCP tool permission gateway | `examples/mcp-tool-permission-gateway` | `python tool_gateway_demo.py` | Govern connector-level and action-level agent tool permissions. |
| PII redaction policy | `examples/pii-redaction-policy` | `python pii_demo.py` | Detect and redact sensitive text before model execution. |
| Regulated RAG assistant | `examples/regulated-rag-assistant` | `python rag_demo.py` | Require citations and stricter controls for regulated-domain answers. |
| Provider routing by risk | `examples/provider-routing-by-risk` | `python routing_demo.py` | Route by risk, region, provider policy, cost, and availability. |
| Audit trace viewer | `examples/audit-trace-viewer` | `python trace_demo.py` | Write traces and generate a local HTML trace viewer. |
| Approval workflow hooks | `examples/approval-workflow-hooks` | `python approval_demo.py` | Send high-risk requests to approval before model execution. |
| Full-stack guardrails | `examples/full-stack-guardrails` | `policyaware guards list examples/full-stack-guardrails/policy.yaml` | Orchestrate optional NeMo Guardrails, Guardrails AI, or custom validators through PolicyAware. |
| Local code scan | `docs/local-code-scan.md` | `policyaware scan ./my-ai-app --format html,json,sarif,markdown` | Scan a repository for AI governance and compliance gaps. |
| YAML policy templates | `docs/yaml-policy-templates.md` | Copy a YAML policy | Start with ready-to-use policy-as-code templates. |
| ML-assisted signals | `docs/ml-integrations.md` | `pip install "policyaware[privacy]"` | Add optional Presidio and ML classifier signals without bloating the base install. |

## Recommended First Path

1. Install with `pip install policyaware`.
2. Run `policyaware init`.
3. Validate the generated policy with `policyaware policy validate policyaware.yaml`.
4. Run `policyaware scan ./my-ai-app`.
5. Try `Gateway.chat(...)` for one controlled LLM request.
6. Add tool governance or callbacks depending on your application architecture.
