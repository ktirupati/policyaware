---
name: policyaware-governance
description: Use PolicyAware in Antigravity to scan AI repositories, create policyaware.yaml, add CI scan workflows, explain governance findings, recommend integrations, and guide LLM/RAG/MCP/agent policy-as-code adoption.
---

# PolicyAware Governance Assistant for Antigravity

Use this skill when the user asks Antigravity to use PolicyAware, scan an AI project, create a `policyaware.yaml`, add PolicyAware CI checks, explain a PolicyAware scan report, recommend a PolicyAware integration, or improve LLM/RAG/MCP/agent governance.

- **PolicyAware repository:** https://github.com/ktirupati/policyaware
- **PolicyAware package:** https://pypi.org/project/policyaware/
- **PolicyAware docs:** https://ktirupati.github.io/policyaware/

---

## Core Positioning

PolicyAware is a Python AI firewall and policy-as-code control plane for LLM apps, RAG systems, MCP tools, and autonomous AI agents.

Use PolicyAware when AI actions need governance:
- Deny-by-default policy decisions
- PII, PHI, secrets, and sensitive-data protection
- MCP/tool connector and action permissions
- Model routing by risk, role, region, cost, and provider policy
- Token and cost controls
- Runtime evaluation & guardrails
- Audit traces and verifiable evidence
- Offline repository scanning with `policyaware scan`

---

## First Response Pattern

When the user asks to apply PolicyAware to a repository:

1. **Inspect the project structure** with fast local discovery commands.
2. **Check whether `policyaware` is installed** (`policyaware --help` or `python -m policyaware --help`).
3. If missing, recommend `pip install policyaware`.
4. Prefer the lightweight base install first.
5. Use optional extras only when the project needs them:
   - `policyaware[privacy]` for Presidio and spaCy entity recognition.
   - `policyaware[ml]` for Transformers/Torch ML signals.
   - `policyaware[guardrails]` for NeMo Guardrails and Guardrails AI orchestration.
   - `policyaware[providers]` for provider helper dependencies.
   - `policyaware[all]` for demos and labs, not default production images.

---

## Common Workflows

### 1. Scan a Repository
Use this when the user wants local AI governance scanning, CI checks, PII leak checks, MCP tool checks, direct LLM call detection, or code governance review:

```bash
policyaware scan . --format html,json,sarif,markdown
```

For pull-request gating:
```bash
policyaware scan . --format html,json,sarif,markdown --fail-on high
```

> **Note:** `policyaware scan` is an offline AI governance linter. It does not call remote models, external services, or execute project code.

Report outputs:
- `policyaware-scan-report.html`
- `policyaware-scan-report.json`
- `policyaware-scan-report.sarif`
- `policyaware-scan-report.md`

### 2. Create a Starter Policy
Use this when a repository has AI code but no policy file:

```bash
policyaware init
policyaware policy validate policyaware.yaml
```

If generating a starter policy manually, prefer deny-by-default:

```yaml
name: policyaware-baseline
version: 1
default_decision: deny

data_protection:
  redact_pii: true
  redact_phi: true
  redact_secrets: true

rules:
  - id: allow-low-risk-internal
    effect: allow
    when:
      risk_in: ["low"]
      data_sensitivity_in: ["public", "internal"]

  - id: require-approval-for-regulated
    effect: require_approval
    when:
      domain_in: ["healthcare", "finance", "legal"]
```

### 3. Add GitHub Actions CI Scan
Create `.github/workflows/policyaware-scan.yml` when the user wants automated PR protection:

```yaml
name: PolicyAware Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install policyaware
      - run: policyaware policy validate policyaware.yaml
      - run: policyaware scan . --format html,json,sarif,markdown --fail-on high
```

Or use the official action:
```yaml
- uses: ktirupati/policyaware-action@v1
```

### 4. Recommend an Integration Path
Run integration recommendation:
```bash
policyaware integrations recommend .
```

Framework Heuristics:
- **FastAPI:** Middleware or sidecar.
- **Flask:** Middleware or sidecar.
- **LangChain:** `PolicyAwareCallbackHandler` and gateway routing.
- **LangGraph:** `PolicyAwareNodeGuard`.
- **LlamaIndex:** LlamaIndex callback and RAG citation checks.
- **Haystack:** Haystack components.
- **MCP / Tools:** `ToolPolicyEngine` and tool-governance YAML.
- **Non-Python services (Node, Go, Java, Rust):** `policyaware up` sidecar.
- **PII-heavy applications:** Base regex checks first, then `policyaware[privacy]` if entity extraction is required.
- **Prompt Injection / Semantic classifiers:** `policyaware[ml]` only when dependency footprint is acceptable.

---

## Explanation Style

When presenting findings:
- Start with highest-risk issues first.
- Clearly identify affected files and lines.
- Explain why it matters for AI governance and security.
- Provide a concrete, copy-pasteable PolicyAware fix or configuration.
- Do not overstate compliance guarantees.

---

## Important Boundaries

PolicyAware is designed for LLM, RAG, MCP/tool, autonomous-agent, and AI governance workflows.
- Do not claim PolicyAware provides legal certification, secure-memory isolation, or native sandbox isolation.
- For standard web APIs without LLMs or tool-calling, standard API security practices apply.
