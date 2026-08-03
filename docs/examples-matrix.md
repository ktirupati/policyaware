# Examples Matrix

Use this table to pick the fastest PolicyAware example for your use case.

| Use Case | Folder Or Doc | Command | What It Proves |
| --- | --- | --- | --- |
| FastAPI LLM policy middleware | `examples/fastapi-llm-policy-middleware` | `python app.py` | Protect an API endpoint before an LLM request reaches a provider. |
| LangChain policy guardrails | `examples/langchain-policy-guardrails` | `python chain_demo.py` | Apply PolicyAware decisions around chain-style LLM calls. |
| LangChain/LlamaIndex callbacks | `docs/capabilities/integration-callbacks.md` | Copy the callback sample | Capture streamed tokens, policy result, output leakage, evals, and token counts. |
| LangGraph agent governance | `examples/langgraph-agent-governance` | `python langgraph_demo.py` | Guard graph state, node execution, and MCP-style tool calls. |
| Haystack RAG governance | `examples/haystack-policyaware-rag-governance` | `python rag_pipeline_demo.py` | Govern Haystack-style RAG queries and generated answers. |
| Haystack agent tool governance | `examples/haystack-policyaware-rag-governance` | `python tool_governance_demo.py` | Add allow, deny, and approval-required decisions before agent tool execution. |
| Microsoft AGT-style interop | `examples/microsoft-agt-interop` | `python agt_interop_demo.py` | Export PolicyAware tool decisions as dependency-free enterprise agent-governance evidence JSON. |
| MCP tool permission gateway | `examples/mcp-tool-permission-gateway` | `python tool_gateway_demo.py` | Govern connector-level and action-level agent tool permissions. |
| PII redaction policy | `examples/pii-redaction-policy` | `python pii_demo.py` | Detect and redact sensitive text before model execution. |
| Regulated RAG assistant | `examples/regulated-rag-assistant` | `python rag_demo.py` | Require citations and stricter controls for regulated-domain answers. |
| Provider routing by risk | `examples/provider-routing-by-risk` | `python routing_demo.py` | Route by risk, region, provider policy, cost, and availability. |
| Audit trace viewer | `examples/audit-trace-viewer` | `python trace_demo.py` | Write traces and generate a local HTML trace viewer. |
| Approval workflow hooks | `examples/approval-workflow-hooks` | `python approval_demo.py` | Send high-risk requests to approval before model execution. |
| Full-stack guardrails | `examples/full-stack-guardrails` | `policyaware guards list examples/full-stack-guardrails/policy.yaml` | Orchestrate optional NeMo Guardrails, Guardrails AI, or custom validators through PolicyAware. |
| Local code scan | `docs/local-code-scan.md` | `policyaware scan ./my-ai-app --format html,json,sarif,markdown` | Scan a repository for AI governance and compliance gaps. |
| Enterprise AI control plane | `examples/enterprise-ai-control-plane` | `python control_plane_demo.py` | Show prompt governance, routing, tool policy, evals, audit, and evidence export together. |
| Policy packs | `examples/policy-packs` | `policyaware policy packs list` | Start from healthcare, finance, EU AI Act, or SOC 2 policy templates. |
| Observability templates | `examples/observability` | `policyaware observability prometheus` | Connect audit traces to Prometheus, Grafana, OTel, SIEM, or GRC workflows. |
| Policy contract checks | `docs/policy-contract-checks.md` | `policyaware contract check ./src --policy tool-governance.yaml` | Prevent YAML/tool signature drift before production. |
| Runnable contract checks | `examples/policy-contract-checks` | `policyaware contract check examples/policy-contract-checks --policy examples/policy-contract-checks/tool-governance.yaml` | Test that MCP/tool YAML still matches Python function signatures. |
| YAML policy templates | `docs/yaml-policy-templates.md` | Copy a YAML policy | Start with ready-to-use policy-as-code templates. |
| ML-assisted signals | `docs/ml-integrations.md` | `pip install "policyaware[privacy]"` | Add optional Presidio and ML classifier signals without bloating the base install. |

## Recommended First Path

1. Install with `pip install policyaware`.
2. Run `policyaware init`.
3. Validate the generated policy with `policyaware policy validate policyaware.yaml`.
4. Run `policyaware scan ./my-ai-app`.
5. Try `Gateway.chat(...)` for one controlled LLM request.
6. Add tool governance or callbacks depending on your application architecture.
