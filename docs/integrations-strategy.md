# PolicyAware Integration Strategy

PolicyAware is a vendor-neutral AI gateway and agent control plane. It should integrate with popular frameworks without becoming tightly coupled to them.

## Core Principle

Keep the base package lightweight:

```bash
pip install policyaware
```

Use optional extras only when a developer needs a heavier framework:

```bash
pip install "policyaware[privacy]"
pip install "policyaware[guardrails]"
pip install "policyaware[haystack]"
pip install "policyaware[providers]"
pip install "policyaware[ml]"
pip install "policyaware[all]"
```

## Official Vs Compatible

PolicyAware uses clear integration language:

| Term | Meaning |
| --- | --- |
| Available | Implemented and tested inside PolicyAware. |
| Optional adapter | Requires an optional third-party package. |
| Compatible | Designed to work with a framework pattern, but not an official partnership. |
| AGT-style | Dependency-free evidence shape inspired by agent governance workflows, not an official Microsoft wire contract. |

Unless explicitly stated, external project names do not imply affiliation, endorsement, or official support from those projects.

## Integration Categories

| Category | Integrations | PolicyAware Role |
| --- | --- | --- |
| App middleware | FastAPI, Flask | Protect API routes before model execution. |
| LLM/RAG frameworks | LangChain, LangGraph, LlamaIndex, Haystack | Add policy checks, output review, token accounting, and audit metadata. |
| Guardrail engines | Guardrails AI, NVIDIA NeMo Guardrails | Orchestrate optional validators inside PolicyAware governance flow. |
| Agent/tool protocols | MCP-style tools | Enforce connector/action permissions, limits, and approvals. |
| Provider platforms | Azure OpenAI, Anthropic, Bedrock, Vertex AI, Ollama, vLLM, OpenAI-compatible | Route requests through policy-aware provider adapters. |
| Governance evidence | Microsoft AGT-style evidence JSON | Export decisions into downstream enterprise governance workflows. |

## CLI Discovery

```bash
policyaware integrations list
policyaware integrations list --json
policyaware integrations recommend .
policyaware integrations recommend . --use-case rag --framework haystack --needs "citations pii audit"
policyaware integrations recommend . --html integration-report.html
```

Use `integrations list` to see install extras, examples, and integration status.

Use `integrations recommend` when you want PolicyAware to inspect project signals and user hints, then recommend the best integration with confidence, reasons, install command, docs, and next steps.

The recommender is rules-based, local, and deterministic. It does not call an LLM or upload project files.

## Recommended Adoption Path

1. Start with `Gateway.chat(...)` or `policyaware scan`.
2. Add framework callbacks for LangChain/LlamaIndex.
3. Add LangGraph node guards if your agent is graph-based.
4. Add MCP/tool governance before tool execution.
5. Add optional Guardrails AI or NeMo Guardrails only when those engines add useful validation.
6. Export audit/evidence artifacts for compliance and security review.

## Smart Recommendation Examples

| Project Signal | Likely Recommendation |
| --- | --- |
| `from fastapi import FastAPI` | FastAPI middleware |
| `from langgraph.graph import StateGraph` | LangGraph agent node guard |
| `langchain` imports | LangChain policy guardrails |
| `haystack` pipeline code | Haystack RAG governance |
| retriever/vector store/citation terms | RAG governance with Haystack or LlamaIndex callbacks |
| MCP/tool/connector/action patterns | MCP/tool permission gateway |
| PII/PHI/privacy/HIPAA terms | Privacy detection and redaction |
| audit/evidence/trace/OTel terms | Audit and AGT-style evidence |
