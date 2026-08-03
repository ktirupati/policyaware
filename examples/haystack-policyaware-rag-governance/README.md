# Haystack PolicyAware RAG Governance

This example shows how PolicyAware can act as an optional governance layer around Haystack-style RAG pipelines and agent tool calls.

Haystack builds the pipeline. PolicyAware provides policy-aware governance:

- prompt/query inspection
- PII, PHI, secrets, and sensitive-data redaction
- risk classification
- YAML policy decisions
- output leakage and citation checks
- MCP-style connector/action tool governance
- reason codes and audit-ready metadata

## Install

Base demo, without installing Haystack:

```bash
pip install policyaware
```

Optional Haystack environment:

```bash
pip install "policyaware[haystack]"
```

The PolicyAware components intentionally avoid a hard Haystack dependency. They expose Haystack-style `run(...)` methods and can be used directly or inserted into Haystack pipelines as lightweight governance components.

## Run RAG Governance Demo

```bash
python rag_pipeline_demo.py
```

Expected output:

```text
input_decision=conditional_allow
governed_query=Summarize the policy for [REDACTED_EMAIL].
output_allowed=True
output_decision=allow
evals=['sensitive_data_leakage', 'citation_required', 'policy_compliance']
```

## Run Tool Governance Demo

```bash
python tool_governance_demo.py
```

Expected output:

```text
read_file_decision=allow
create_pr_decision=require_approval
create_pr_approval_required=True
delete_branch_decision=deny
```

## Integration Pattern

```text
User query
  -> PolicyAwareInputComponent
  -> Haystack Retriever / PromptBuilder / Generator
  -> PolicyAwareOutputComponent
  -> Answer
```

For agent tools:

```text
Haystack Agent Tool Request
  -> PolicyAwareToolGovernanceComponent
  -> allow / deny / require_approval
  -> execute tool only when allowed
```

## Example Policy

`policyaware.yaml` is deny-by-default:

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

## Why This Exists

Haystack is strong at building RAG and agent pipelines. PolicyAware complements it by adding enterprise governance controls around those pipelines without forcing a new model provider or orchestration style.
