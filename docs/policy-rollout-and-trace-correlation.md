# Policy Rollout And Trace Correlation

PolicyAware supports safer production policy changes through shadow evaluation, canary enforcement, and parent/child trace correlation.

## Shadow Policy Evaluation

Shadow mode evaluates a candidate policy and records what would have changed, but still enforces the current policy.

```bash
policyaware up \
  --policy policyaware.yaml \
  --rollout-policy candidate-policy.yaml \
  --rollout-mode shadow \
  --rollout-percentage 100 \
  --require-auth
```

Response metadata includes:

```json
{
  "policy_rollout": {
    "name": "candidate",
    "mode": "shadow",
    "percentage": 100,
    "primary_decision": "allow",
    "candidate_decision": "deny",
    "changed": true
  }
}
```

## Canary Enforcement

Canary mode enforces the candidate policy only for the selected traffic percentage.

```bash
policyaware up \
  --policy policyaware.yaml \
  --rollout-policy candidate-policy.yaml \
  --rollout-mode enforce \
  --rollout-percentage 10 \
  --require-auth
```

Use this after shadow results show acceptable deny, approval, latency, and safety behavior.

## Python SDK

```python
from policyaware import Gateway, PolicyRollout

gateway = Gateway.from_policy_file("policyaware.yaml")
gateway.policy_rollout = PolicyRollout.from_file(
    "candidate-policy.yaml",
    mode="shadow",
    percentage=100,
)
```

## Trace Correlation

PolicyAware audit traces now include:

- `parent_trace_id`
- `session_id`

Pass these fields in request context or metadata:

```json
{
  "context": {
    "session_id": "claim-session-42",
    "parent_trace_id": "trc_parent_123"
  }
}
```

This helps connect one user request to downstream model calls, tool calls, and multi-agent workflow steps.

## Governance Dashboard

Generate a static dashboard from JSONL audit traces:

```bash
policyaware audit dashboard .policyaware/traces.jsonl --out .policyaware/governance-dashboard.html
```

Or from SQLite audit storage:

```bash
policyaware audit dashboard-sqlite --db .policyaware/audit.db --out .policyaware/governance-dashboard.html
```

The dashboard summarizes decisions, risk tiers, top applications, estimated cost, average latency, signed trace count, sessions, and parent trace relationships.

