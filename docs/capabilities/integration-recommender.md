# Integration Recommender

PolicyAware includes an explainable integration recommender that scans a project and combines detected code signals with optional user hints.

It is rules-based, local, and deterministic. It does not call an LLM or send project code outside your machine.

## Why It Exists

Users often ask:

- Should I use FastAPI middleware or Gateway?
- Should I use LangChain callbacks or LangGraph node guards?
- Should I use Haystack, LlamaIndex, MCP tool governance, Guardrails AI, NeMo Guardrails, or audit evidence export?
- Which optional extra should I install?

The recommender answers with a ranked recommendation and explains why.

## CLI Usage

Scan the current project:

```bash
policyaware integrations recommend .
```

Add user hints:

```bash
policyaware integrations recommend . --use-case rag --framework haystack --needs "citations pii audit"
```

Return machine-readable JSON:

```bash
policyaware integrations recommend . --json
```

Generate an HTML report:

```bash
policyaware integrations recommend . --html integration-report.html
```

Limit results:

```bash
policyaware integrations recommend . --top 5
```

## Example Output

```text
Recommended Integrations

1  LangGraph agent node guard  0.95
   Why: Detected LangGraph StateGraph/ToolNode patterns; Detected agent/tool execution patterns; No tool-governance policy detected yet.
   Install: pip install policyaware
   Example: examples/langgraph-agent-governance
```

## Python Usage

```python
from policyaware import IntegrationRecommender

report = IntegrationRecommender().recommend(
    ".",
    use_case="agent",
    framework="langgraph",
    needs="pii audit tools",
)

best = report.best
print(best.name)
print(best.confidence)
print(best.reasons)
print(best.install)
print(best.example)
```

## Signals It Looks For

| Signal | Examples |
| --- | --- |
| Framework imports | `FastAPI`, `langchain`, `StateGraph`, `llama_index`, `haystack` |
| RAG patterns | retriever, vector store, embeddings, citations, grounding |
| Agent patterns | agent executors, tool calls, `bind_tools`, planners, executors |
| MCP/tool governance | MCP, connector/action patterns, `tool-governance.yaml` |
| Privacy needs | PII, PHI, privacy, HIPAA, patient, SSN, API key |
| Audit needs | audit, evidence, traces, OpenTelemetry, Prometheus |
| Provider needs | Azure OpenAI, Anthropic, Bedrock, Vertex AI, Ollama, vLLM |
| Existing PolicyAware files | `policyaware.yaml`, `tool-governance.yaml` |

## HTML Report

The HTML report is designed for enterprise reviewers and developer onboarding.
It includes:

- best recommendation
- confidence
- install command
- example path
- ranked alternatives
- detected project signals
- next steps

## Recommendation Output

```json
{
  "name": "LangGraph agent node guard",
  "score": 95,
  "confidence": 0.95,
  "install": "pip install policyaware",
  "example": "examples/langgraph-agent-governance",
  "docs": "docs/capabilities/langgraph-integration.md",
  "reasons": [
    "Detected LangGraph StateGraph/ToolNode patterns.",
    "Detected agent/tool execution patterns."
  ],
  "next_steps": [
    "Wrap graph nodes with `PolicyAwareNodeGuard`.",
    "Add `tool-governance.yaml` before tool execution."
  ]
}
```

## Design Notes

The recommender intentionally starts with rules-based scoring instead of ML:

- recommendations are explainable
- no project data leaves the machine
- no model download is required
- results are stable enough for documentation and CI workflows

Future versions can add optional ML-assisted project classification, but rules should remain the final explainable layer.
