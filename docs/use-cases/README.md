# PolicyAware Use-Case Guides

PolicyAware is a Python AI firewall and policy-as-code control plane for LLM apps, RAG systems, MCP tools, and autonomous AI agents.

These guides are written around common developer searches. Each page explains the problem, shows a copy-paste YAML policy, and gives a Python or CLI example.

## AI Firewall And Zero-Trust Agent Governance

Use these when your team needs to stop unsafe agent actions, block tool misuse, or prevent runaway loops before an LLM or agent reaches production.

- [AI Firewall For LLM Agents](ai-firewall-for-llm-agents.md)
- [MCP Tool Permission Gateway](mcp-tool-permission-gateway.md)

Search intents these pages answer:

| Search Intent | PolicyAware Fit |
| --- | --- |
| how to stop autonomous agent runaway loop | Token budgets, tool budgets, risk tiers, and approval gates |
| intercept model context protocol mcp tools python | MCP-style connector and action policy checks |
| deterministic ai firewall local pip package | Local deny-by-default Python policy enforcement |
| deny-by-default llm gateway | Gateway decisions default to deny unless policy allows |

## AI GitOps And Policy-As-Code

Use these when security, platform, or compliance teams need central policy definitions, CI checks, remote distribution, and fail-closed behavior.

- [Policy-As-Code For LLMs](policy-as-code-for-llms.md)
- [Centralized AI Policy Distribution](centralized-ai-policy-distribution.md)

Search intents these pages answer:

| Search Intent | PolicyAware Fit |
| --- | --- |
| centralized yaml policy distribution s3 gcs | HTTP, S3, GCS, ADLS Gen2, local cache, and emergency fallback |
| cryptographically pinned remote compliance policy | Checksum validation and last-known-good policy cache |
| scan github repository for ai security leaks | `policyaware scan` plus GitHub Action/SARIF workflows |
| fail-closed llm security gateway architecture | Deny-by-default fallback when policy loading fails |

## Data Protection And FinOps

Use these when prompts may contain PII, PHI, secrets, customer data, or uncontrolled token usage.

- [PII Redaction Before LLM Calls](pii-redaction-before-llm.md)
- [LLM Token Budget And Cost Controls](llm-token-budget-cost-controls.md)
- [LLM Audit Logging And OpenTelemetry](llm-audit-logging-opentelemetry.md)

Search intents these pages answer:

| Search Intent | PolicyAware Fit |
| --- | --- |
| redact pii secrets before prompt leaves infrastructure | DataProtectionEngine and policy-based redaction |
| python llm token budget rate limiting | Budget, token, routing, and agent-loop controls |
| open telemetry hookups for blocked ai actions | Structured rejection payloads and OTel-shaped events |

## Related Documentation

- [Capabilities](../capabilities.md)
- [Comparison: PolicyAware vs guardrails vs AI gateway vs model router](../comparison.md)
- [Security Boundaries](../security-boundaries.md)
- [Dynamic Policy Distribution](../dynamic-policy-distribution.md)
- [Policy Composition](../policy-composition.md)
- [Local Code Scan](../local-code-scan.md)
