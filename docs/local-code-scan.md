# PolicyAware Local Code Scan

`policyaware scan` scans a local folder quickly and generates a user-friendly HTML report with findings, recommendations, and PolicyAware documentation links.

It is designed for developers who want to answer:

> What AI governance risks exist in my local app, and how do I fix them with PolicyAware?

## Install

```bash
pip install policyaware
```

## Quick Start

```bash
policyaware scan ./mylocalfolder
```

Default output:

```text
policyaware-scan-report.html
```

Custom output:

```bash
policyaware scan ./mylocalfolder --out reports/policyaware-scan-report.html
```

Open the report automatically:

```bash
policyaware scan ./mylocalfolder --open
```

Use more workers:

```bash
policyaware scan ./mylocalfolder --workers 8
```

Use a scan config file:

```bash
policyaware scan ./mylocalfolder --config policyaware-scan.yaml
```

Scan only changed files:

```bash
policyaware scan ./mylocalfolder --diff --diff-base origin/main
```

Write multiple report formats with one option:

```bash
policyaware scan ./mylocalfolder --format html,json,sarif,markdown
```

Write a JSON report for CI or automation:

```bash
policyaware scan ./mylocalfolder --json policyaware-scan-report.json
```

Write SARIF for code scanning integrations:

```bash
policyaware scan ./mylocalfolder --sarif policyaware.sarif
```

Write Markdown for pull requests or review tickets:

```bash
policyaware scan ./mylocalfolder --markdown policyaware-scan-report.md
```

Ignore known noisy paths:

```bash
policyaware scan ./mylocalfolder --ignore-file .policyawareignore
```

Use a baseline of accepted findings:

```bash
policyaware scan ./mylocalfolder --baseline policyaware-baseline.json
policyaware scan ./mylocalfolder --write-baseline policyaware-baseline.json
```

Fail CI when high or critical findings exist:

```bash
policyaware scan ./mylocalfolder --fail-on high
```

Control scan scope:

```bash
policyaware scan ./mylocalfolder --include ".py,.yaml,.json"
policyaware scan ./mylocalfolder --exclude "tests,fixtures"
```

Scan larger files:

```bash
policyaware scan ./mylocalfolder --max-file-size 1mb
```

## What It Checks

The fast local scanner checks:

| Area | Examples | Recommendation |
| --- | --- | --- |
| PII | Emails, phone numbers, SSNs, credit card-like values | Redact before prompts reach models, tools, logs, or evals. |
| PHI | Patient IDs, medical records, diagnosis/prescription language | Use regulated-domain policies and redaction. |
| Secrets | API keys, tokens, bearer tokens, secret assignments | Move to environment variables or secret managers and rotate exposed keys. |
| Direct LLM calls | OpenAI, Anthropic, Bedrock, Vertex, LiteLLM, Ollama, vLLM/OpenAI-compatible requests, LlamaIndex, DSPy, Semantic Kernel, LangChain-style calls | Route through `Gateway.chat(...)` before execution. |
| Tool governance | Delete, deploy, merge, refund, payment, transfer style actions | Add connector/action policy and approval requirements. |
| Agent tool governance | MCP tools, LangChain tools, CrewAI tools, AutoGen/function-calling/tool-call patterns | Require connector-level and action-level permissions. |
| Provider governance | Provider/framework usage without PolicyAware routing | Route by approved provider, role, risk, region, cost, and availability policy. |
| Data residency | External endpoints, regions, API bases, cloud locations | Add tenant, region, and compliance constraints before regulated data leaves approved boundaries. |
| Autonomous agent governance | `while True`, `agent.run`, auto-execute, long-running autonomous loops | Add human approval, max iterations, budgets, and audit logs. |
| Cost governance | Model or agent calls without token, timeout, rate, retry, or cost limits | Define request-level and workflow-level limits. |
| Prompt safety | Prompt templates with bypass, ignore-instructions, reveal-system-prompt, or execute-without-approval language | Add prompt safety checks and approvals for autonomous actions. |
| Guardrails integration | Direct NeMo Guardrails or Guardrails AI usage outside PolicyAware orchestration, missing guard config paths, custom guards without markers, guard policies without `when` conditions | Attach guardrails through PolicyAware adapters so guard results are audited and policy-aware. |
| RAG governance | Retrieval, vectorstore, similarity search, embedding code | Add grounding and citation evaluation. |
| Data pipeline governance | PySpark, Spark reads/writes, streaming, cloud storage paths, sensitive column names | Mask sensitive columns and audit data writes. |
| Configuration governance | `.env`, YAML, JSON, Terraform, Docker, and CI/CD style files with sensitive config context | Use secret manager references and avoid plaintext secrets. |
| Audit gaps | Model calls without trace/audit language | Capture request, decision, route, eval result, and response metadata. |
| YAML policy quality | Policy schema errors and missing `default: deny` | Validate policies and keep deny-by-default behavior. |

## Supported File Types

The scanner is strongest for AI application and policy code. It scans common source, config, data, and notebook files:

```text
.py, .js, .jsx, .ts, .tsx, .java, .scala, .kt, .go, .rs, .sh
.yml, .yaml, .json, .toml, .ini, .properties, .env
.ipynb, .sql, .tf, .hcl, Dockerfile
.md, .txt, .example, .sample
```

## Fast By Default

The scanner is optimized for quick local use:

- No network calls.
- No model calls.
- No ML model loading.
- Does not execute project code.
- Scans files in parallel.
- Skips noisy folders such as `.git`, `.venv`, `node_modules`, `dist`, `build`, `.next`, and caches.
- Scans useful text/code files such as Python, JavaScript, TypeScript, YAML, JSON, Markdown, text, and env examples.
- Extracts code and markdown text from Jupyter notebooks.
- Skips files larger than `512kb` by default.

## Example Report Summary

```text
Overall risk: High
Files scanned: 184
Files skipped: 927
Findings: 12
Critical: 2
High: 4
Medium: 5
Low: 1
Scan time: 3.8s
HTML report: policyaware-scan-report.html
```

## HTML Report Sections

The generated report includes:

- Executive summary.
- Overall risk.
- Files scanned and skipped.
- Severity counts.
- Finding categories.
- Top recommendations.
- Findings table.
- Findings grouped by file.
- Redacted evidence.
- Copy-paste PolicyAware gateway example.
- Starter YAML policy.
- Links to PolicyAware documentation.
- Interactive filters by text, severity, and category.
- Interactive filter by compliance area.
- Stable finding fingerprints for baselines and CI.
- Policy coverage score and inferred governance gaps.
- Governance reviewer summary.
- Compliance area counts.
- Suggested fix snippets per finding.
- Remediation checklist.

## Compliance Areas

Every finding is mapped to a reviewer-friendly compliance area so policy, security, and governance teams can triage quickly.

| Finding Category | Compliance Area |
| --- | --- |
| Secrets | Security / Secrets Management |
| PII | Privacy / Data Protection |
| PHI | Regulated Data / Healthcare Privacy |
| LLM Governance | Model Governance |
| Provider Governance | Provider Governance |
| Data Residency | Region / Data Residency |
| Tool Governance | Human Oversight / Tool Governance |
| Agent Tool Governance | Agent Tool Governance |
| Autonomous Agent Governance | Human Oversight |
| Cost Governance | Cost / Usage Governance |
| RAG Governance | Grounding / RAG Governance |
| Auditability | Auditability |
| Policy YAML | Policy Governance |
| Data Pipeline Governance | Data Pipeline Governance |
| Configuration Governance | Secure Configuration |
| Prompt Safety | Prompt Safety |

## Ignore File

Create `.policyawareignore` in the scan root to skip noisy paths.

```text
tests/fixtures/**
docs/**
examples/demo-secrets.py
```

You can also pass a custom file:

```bash
policyaware scan . --ignore-file config/policyaware-ignore.txt
```

## Inline Suppressions

Use inline suppressions for intentional examples, test fixtures, or already-reviewed findings.

Suppress the next line:

```python
# policyaware-ignore-next-line: documented test credential
OPENAI_API_KEY = "sk_test_abcdefghijklmnop"
```

Suppress the current line:

```python
OPENAI_API_KEY = "sk_test_abcdefghijklmnop"  # policyaware-ignore-line: fixture
```

Suppress a whole file:

```python
# policyaware-ignore-file: generated fixture
```

Use suppressions sparingly. For real findings, prefer fixing the code or using `.policyawareignore` for generated folders.

## Scan Config YAML

Create `policyaware-scan.yaml` when teams need consistent scan behavior across local development and CI.

```yaml
scan:
  include_extensions:
    - .py
    - .yaml
    - .json
    - .ipynb
    - .tf

  exclude_dirs:
    - tests/fixtures
    - generated

  ignore_patterns:
    - docs/examples/**

  disabled_categories:
    - Provider Governance

  severity_overrides:
    Data Residency: high
    Cost Governance: low

  max_file_size: 1mb
  max_findings_per_file: 30
```

Run it:

```bash
policyaware scan . --config policyaware-scan.yaml --format html,json,sarif,markdown
```

Use `enabled_categories` when you want a narrow scan:

```yaml
scan:
  enabled_categories:
    - Secrets
    - PII
    - PHI
    - Configuration Governance
```

## Git Diff Scanning

Use diff scanning in pull requests to scan only files changed against a base ref.

```bash
policyaware scan . --diff --diff-base origin/main --fail-on high
```

This keeps CI fast for large repositories while still allowing a full scheduled scan.

## Baseline

Use a baseline when you want to accept known findings and only focus on new findings.

Create a baseline:

```bash
policyaware scan . --write-baseline policyaware-baseline.json
```

Use the baseline later:

```bash
policyaware scan . --baseline policyaware-baseline.json --fail-on high
```

Baseline files contain stable finding fingerprints:

```json
{
  "schema_version": "0.1",
  "tool": "policyaware",
  "fingerprints": [
    "policyaware:abc123..."
  ]
}
```

## JSON Report

Use JSON when you want a machine-readable result for CI, dashboards, or a future local PolicyAware agent.

```bash
policyaware scan . --json policyaware-scan-report.json
```

Top-level JSON fields include:

```json
{
  "scanned_path": "./mylocalfolder",
  "output_path": "policyaware-scan-report.html",
  "generated_at": "2026-07-21 10:30:00 EDT",
  "duration_seconds": 2.35,
  "files_scanned": 184,
  "files_skipped": 927,
  "suppressed_findings": 1,
  "overall_risk": "High",
  "policy_coverage_score": 78,
  "policy_coverage_missing": [
    "secret handling",
    "gateway enforcement before model calls"
  ],
  "governance_posture": {
    "readiness": "Needs remediation before production release",
    "release_blockers": 3,
    "policy_coverage_score": 78,
    "top_categories": [
      {
        "category": "Secrets",
        "count": 2
      }
    ]
  },
  "severity_counts": {
    "critical": 2,
    "high": 4
  },
  "category_counts": {
    "Secrets": 2,
    "LLM Governance": 3
  },
  "compliance_counts": {
    "Security / Secrets Management": 2,
    "Model Governance": 3
  },
  "compliance_framework_mapping": {
    "SOC 2": [
      "Secrets"
    ],
    "AI Governance": [
      "LLM Governance"
    ]
  },
  "scanned_files": [
    "app.py",
    "policyaware.yaml"
  ],
  "findings": []
}
```

## CI Exit Codes

By default, `policyaware scan` exits with code `0` even when findings exist, because local developer scans should be informational.

Use `--fail-on` in CI:

```bash
policyaware scan . --fail-on critical
policyaware scan . --fail-on high
policyaware scan . --fail-on medium
```

Accepted values:

```text
critical
high
medium
low
none
```

## SARIF Output

Use SARIF when you want to import PolicyAware scan findings into tools that understand static-analysis results.

```bash
policyaware scan . --sarif policyaware.sarif
```

The SARIF output includes:

- rule IDs by PolicyAware category
- severity mapped to SARIF levels
- file path and line number
- redacted evidence
- compliance area
- suggested fix snippet
- PolicyAware recommendation text

## Markdown Output

Use Markdown when you want a compact report in pull requests, Jira tickets, GitHub issues, or compliance review notes.

```bash
policyaware scan . --markdown policyaware-scan-report.md
```

The Markdown report includes:

- executive scan summary
- severity counts
- top recommendations
- findings table with file, line, category, and compliance area

## Example Governance Findings

Direct model provider call without PolicyAware:

```python
import anthropic

client = anthropic.Anthropic()
response = client.messages.create(model="claude-test", messages=[])
```

Recommended pattern:

```python
from policyaware import Gateway, GatewayRequest

gateway = Gateway.from_policy_file("policyaware.yaml")
response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="assistant",
        user={"id": "user_123", "role": "developer"},
        context={"region": "us", "risk": "medium"},
        messages=[{"role": "user", "content": prompt}],
    )
)
```

Autonomous agent execution without oversight:

```python
while True:
    agent.run("deploy to production")
```

Policy pattern:

```yaml
agent_controls:
  max_iterations: 5
  require_approval_for: [write, delete, deploy, payment]
  audit_each_tool_call: true
```

Provider and region policy pattern:

```yaml
routing:
  strategy: policy_aware
  providers:
    - name: internal-local
      type: local
      allowed_for: [sensitive, regulated, high]
    - name: external-approved
      type: external
      allowed_for: [public, low, medium]

rules:
  - name: regulated_data_requires_approved_region
    effect: deny
    when:
      data.contains_phi: true
      context.region_not_in: [us-east, us-west]
```

## CI Templates

Ready-to-copy templates are available in:

- `docs/ci/policyaware-scan-github-actions.yml`
- `docs/ci/azure-pipelines-policyaware-scan.yml`
- `docs/ci/gitlab-ci-policyaware-scan.yml`

## Evidence Is Redacted

The report avoids exposing full sensitive values.

Examples:

```text
jane@example.com -> [REDACTED_EMAIL]
sk_test_abcdefghijklmnop -> [REDACTED_SECRET]
123-45-6789 -> [REDACTED_SSN]
```

## Copy-Paste Gateway Fix

```python
from policyaware import Gateway, GatewayRequest

gateway = Gateway.from_policy_file("policyaware.yaml")

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="local-ai-app",
        user={"id": "user_123", "role": "developer"},
        context={"region": "us", "risk": "medium", "task_type": "code_assistant"},
        messages=[{"role": "user", "content": user_prompt}],
    )
)

print(response.policy.decision)
print(response.policy.reason_codes)
```

## Starter YAML Policy

```yaml
id: local_ai_governance_policy
schema_version: "0.2"
default: deny

rules:
  - name: deny_secrets
    effect: deny
    when:
      data.contains_secrets: true

  - name: redact_pii
    effect: transform
    action: redact
    when:
      data.contains_pii: true

  - name: require_approval_for_high_risk
    effect: require_approval
    when:
      risk.tier_in: [high, critical]

  - name: allow_low_medium_risk_developers
    effect: allow
    when:
      user.role_in: [developer, platform_engineer]
      risk.tier_in: [low, medium]
```

## Recommended Workflow

```bash
policyaware scan .
```

Open the report, fix critical findings first, then scan again:

```bash
policyaware scan . --out policyaware-scan-report.html
```

For CI, keep the HTML report as an artifact so reviewers can inspect governance findings.
