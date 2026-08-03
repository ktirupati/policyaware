# Stateful Session Governance

PolicyAware can perform lightweight stateful inspection across a conversation, user session, or agent run.

This helps detect slow exfiltration patterns where each individual request looks harmless, but the session accumulates sensitive data or repeated tool activity over time.

## Why This Matters

Stateless checks answer:

```text
Is this single prompt or tool call allowed?
```

Stateful checks add:

```text
Has this session gradually leaked too much sensitive data?
Is this agent repeatedly calling the same tool in a suspicious pattern?
Has this conversation crossed a cumulative risk threshold?
```

## Enable In The Sidecar

```bash
policyaware up \
  --policy policyaware.yaml \
  --tool-policy tool-governance.yaml \
  --session-state \
  --max-session-sensitive-findings 10 \
  --max-session-tool-calls 25 \
  --max-same-tool-action 10 \
  --require-auth
```

When enabled, `/v1/check` and `/v1/tool/check` include session state in the response metadata.

## Session Identity

PolicyAware resolves session identity from:

1. `metadata.session_id`
2. `context.session_id`
3. `context.conversation_id`
4. `user.id`
5. fallback tenant/app or tenant/agent identity

Example request:

```json
{
  "tenant": "acme",
  "app": "claims-assistant",
  "user": {"id": "u_123", "role": "support_agent"},
  "context": {
    "session_id": "claim-session-42",
    "region": "us",
    "risk": "low",
    "task_type": "support"
  },
  "prompt": "Email jane@example.com about the claim."
}
```

## Python SDK

```python
from policyaware import Gateway, GatewayRequest, SessionStateMonitor

gateway = Gateway.from_policy_file("policyaware.yaml")
gateway.session_monitor = SessionStateMonitor(
    max_sensitive_findings_per_session=10,
    max_tool_calls_per_session=25,
    max_same_tool_action_per_session=10,
)

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="claims-assistant",
        user={"id": "u_123", "role": "support_agent"},
        context={"session_id": "claim-session-42", "region": "us", "risk": "low"},
        messages=[{"role": "user", "content": "Email jane@example.com"}],
    )
)

print(response.policy.decision)
print(response.metadata.get("session"))
```

## Tool-Call Pattern Detection

For MCP/tool governance, PolicyAware tracks:

- total tool calls in the session
- repeated calls to the same connector/action
- session-level denial when thresholds are crossed

Example signal:

```json
{
  "decision": "deny",
  "reason_codes": ["SESSION.TOOL_CALL_LIMIT_EXCEEDED"],
  "session": {
    "session_id": "agent-session-1",
    "tool_calls": 26,
    "tool_actions": {
      "github.read_file": 26
    }
  }
}
```

## Current Storage Model

The default monitor is in-memory and process-local. It is useful for:

- local development
- single sidecar deployments
- CI simulations
- early production hardening

For restart-tolerant local or small production deployments, use SQLite:

```bash
policyaware up \
  --policy policyaware.yaml \
  --tool-policy tool-governance.yaml \
  --session-state \
  --session-state-store sqlite \
  --session-state-db .policyaware/session-state.db \
  --require-auth
```

For multi-replica production systems, place the sidecar behind sticky sessions or extend `SessionStateMonitor` with a shared backing store such as Redis, Postgres, or a streaming audit pipeline.

The current feature gives PolicyAware a native stateful inspection primitive without forcing a database dependency into the base package.
