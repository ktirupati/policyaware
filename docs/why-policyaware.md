# Why PolicyAware

PolicyAware exists because AI applications now do more than generate text.

Modern LLM systems retrieve internal documents, call MCP servers, query databases, write files, create pull requests, route across model providers, and trigger business workflows. A content filter alone cannot govern those actions.

PolicyAware is the policy and audit layer for AI actions.

## The Core Idea

PolicyAware answers four questions before an AI workflow continues:

1. Is this user, tenant, region, and task allowed?
2. Does the prompt, retrieved context, or tool argument contain sensitive data?
3. Is the requested model, provider, or tool action approved for this risk level?
4. Can the decision be explained later with reason codes and audit evidence?

## What PolicyAware Is

- A deny-by-default policy engine for LLM, RAG, MCP, and agent workflows.
- A local code scanner for AI governance gaps before deployment.
- A tool-governance layer for MCP-style connectors and actions.
- A data-protection layer for PII, PHI, secrets, and sensitive prompts.
- An audit and evidence layer for security and compliance review.

## What PolicyAware Is Not

- It is not a hosted SaaS dashboard.
- It is not a replacement for legal, compliance, or security review.
- It is not an OS-level sandbox for executing untrusted tools.
- It is not a claim that every optional integration is required.
- It is not a Rust/C native accelerator today; benchmark claims should be measured in the target environment.

## Stable Core First

The strongest production path is intentionally small:

```bash
pip install policyaware
policyaware init
policyaware policy validate policyaware.yaml
policyaware scan . --format html,json,sarif,markdown
```

Then add only what the application needs:

- `Gateway.inspect_and_mutate(...)` for raw OpenAI/Anthropic-style preflight.
- `ToolPolicyEngine` for application-owned tool calls.
- `MCPPolicyProxy` for raw MCP JSON-RPC `tools/call` requests.
- `policyaware[privacy]` for stronger Presidio/spaCy privacy detection.
- `policyaware[ml]` or `policyaware[guardrails]` only for services that need heavier semantic or guardrail stacks.

## Best First Demo

The clearest demonstration is MCP governance:

```bash
python examples/mcp-policy-proxy-demo/mcp_proxy_demo.py
```

This shows PolicyAware intercepting raw MCP JSON-RPC tool calls, redacting sensitive arguments, requiring approval for writes, and denying destructive actions before an MCP server executes them.

## One-Sentence Positioning

PolicyAware is an open-source Python AI governance layer for teams that need deny-by-default policy, sensitive-data protection, MCP/tool permissions, local code scanning, and audit evidence around LLM, RAG, and agent workflows.

