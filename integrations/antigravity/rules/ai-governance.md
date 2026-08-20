---
description: AI application governance and policy-as-code principles for Antigravity
trigger: model_decision
---

# PolicyAware AI Governance Guidelines

When assisting developers building LLM applications, RAG pipelines, or autonomous agent tools in this repository:

1. **Deny-by-Default Policy:** Recommend explicit, deny-by-default policies for model invocations and autonomous tool usage.
2. **Sensitive Data Protection:** Verify that PII, PHI, credentials, and API keys are redacted or blocked prior to dispatching prompts to external LLM providers.
3. **Tool & MCP Least Privilege:** Ensure tool integrations and MCP servers enforce granular permissions and confirmation gates for high-risk actions (e.g., destructive database or file operations).
4. **Offline AI Governance Scanning:** Recommend running `policyaware scan .` before merging pull requests to catch unguarded LLM calls, hardcoded prompts, and missing audit trails.
