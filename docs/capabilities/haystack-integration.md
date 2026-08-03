# Haystack Integration

PolicyAware can be used as an optional governance layer for Haystack-style RAG pipelines and agent workflows.

Haystack builds the orchestration pipeline. PolicyAware adds enterprise policy checks around that pipeline:

- query/prompt inspection
- PII, PHI, secrets, and sensitive-data redaction
- risk-tier classification
- deny, allow, conditional allow, and approval-required decisions
- RAG output leakage and citation checks
- MCP-style tool/action governance
- reason codes and audit-ready metadata

## Install

Base package:

```bash
pip install policyaware
```

Optional Haystack environment:

```bash
pip install "policyaware[haystack]"
```

The integration classes do not require Haystack at import time. They expose Haystack-style `run(...)` methods so the base install remains lightweight.

## APIs

| API | Purpose |
| --- | --- |
| `PolicyAwareInputComponent` | Inspect and optionally redact a query before retrieval, prompt building, or generation. |
| `PolicyAwareOutputComponent` | Evaluate generated RAG answers for leakage, citations, and policy consistency. |
| `PolicyAwareToolGovernanceComponent` | Govern Haystack agent tool calls by connector, action, role, arguments, and approval requirements. |
| `PolicyAwareHaystackResult` | JSON-ready result object for component-level governance metadata. |

## RAG Query Guard

```python
from policyaware.integrations.haystack import PolicyAwareInputComponent

guard = PolicyAwareInputComponent(
    config="policyaware.yaml",
    tenant="acme",
    user={"id": "u_123", "role": "analyst"},
    context={"region": "us", "risk": "low", "task_type": "rag_query"},
)

result = guard.run(query="Summarize the policy for jane@example.com.")

print(result["decision"])
print(result["query"])
print(result["policyaware"]["reason_codes"])
```

Expected behavior:

- PII is detected.
- The policy may return `conditional_allow`.
- The query is redacted before it continues through the RAG pipeline.

## RAG Output Evaluation

```python
from policyaware.integrations.haystack import PolicyAwareOutputComponent

output_guard = PolicyAwareOutputComponent(
    config="policyaware.yaml",
    context={"region": "us", "risk": "low", "task_type": "rag_answer", "require_citations": True},
)

result = output_guard.run(
    query="Summarize support policy.",
    answer="Support requests must cite the governing policy [policy-doc-1].",
)

print(result["allowed"])
print(result["policyaware"]["evals"])
```

## Agent Tool Governance

```python
from policyaware.integrations.haystack import PolicyAwareToolGovernanceComponent

tool_guard = PolicyAwareToolGovernanceComponent(
    tool_policy="tool-governance.yaml",
    agent_id="haystack_agent",
    user={"id": "u_456", "role": "developer"},
    context={"region": "us", "risk": "medium", "task_type": "agent_tool_call"},
)

decision = tool_guard.run(
    connector_id="github",
    action="create_pr",
    arguments={"repo": "ktirupati/policyaware", "title": "Update docs"},
)

print(decision["decision"])
print(decision["approval_required"])
```

## Copy-Paste Policy

```yaml
id: haystack_policyaware_rag_governance
default: deny

rules:
  - name: block_secrets
    effect: deny
    when:
      data.contains_secrets: true

  - name: allow_haystack_rag_users
    effect: allow
    when:
      user.role_in: ["developer", "analyst", "support_agent"]
      request.region: "us"
      request.risk_in: ["low", "medium"]

  - name: redact_pii_for_rag_queries
    effect: transform
    action: redact
    when:
      data.contains_pii: true
      user.role_not_in: ["privacy_admin", "compliance_officer"]
```

## Example

Run the complete example:

```bash
cd examples/haystack-policyaware-rag-governance
python rag_pipeline_demo.py
python tool_governance_demo.py
```

Example folder:

```text
examples/haystack-policyaware-rag-governance/
  README.md
  policyaware.yaml
  tool-governance.yaml
  rag_pipeline_demo.py
  tool_governance_demo.py
  terminal-output.txt
```

## Positioning

PolicyAware does not replace Haystack. It complements Haystack by acting as an external policy decision and governance layer for enterprise RAG and agent workflows.
