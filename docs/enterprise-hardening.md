# Enterprise Hardening

PolicyAware includes optional hardening primitives for production-style deployments.

These features are additive and dependency-light. They are intended to strengthen open-source deployments without requiring a managed control-plane service.

## SQLite-Backed Session State

The default `SessionStateMonitor` is in-memory. For one process this is fine, but multi-worker or restart-tolerant deployments can use SQLite:

```bash
policyaware up \
  --policy policyaware.yaml \
  --tool-policy tool-governance.yaml \
  --session-state \
  --session-state-store sqlite \
  --session-state-db .policyaware/session-state.db \
  --require-auth
```

Python:

```python
from policyaware import Gateway, SessionStateMonitor, SQLiteSessionStateStore

gateway = Gateway.from_policy_file("policyaware.yaml")
gateway.session_monitor = SessionStateMonitor(
    store=SQLiteSessionStateStore(".policyaware/session-state.db"),
)
```

For horizontally scaled production with many replicas, use sticky sessions or implement a shared store backed by Redis, Postgres, or your platform state service.

## Emergency Revoke List

Emergency revoke rules run before normal policy and tool decisions.

Example `emergency-revoke.yaml`:

```yaml
rules:
  - name: revoke_customer_write_actions
    reason: Emergency shutdown for customer write actions.
    when:
      request.action_type_in:
        - write
        - delete
      request.domain: customer_data

  - name: revoke_github_delete_branch
    reason: Emergency shutdown for GitHub branch deletion.
    when:
      tool.connector: github
      tool.action: delete_branch
```

Use it:

```bash
policyaware up \
  --policy policyaware.yaml \
  --tool-policy tool-governance.yaml \
  --revoke-file emergency-revoke.yaml \
  --require-auth
```

This gives compliance or security teams a fast kill-switch pattern that can be distributed separately from normal policy files.

## Policy Checksum Pinning

Use checksum pinning to reject stale, downgraded, or tampered policy artifacts:

```bash
policyaware up \
  --policy-url s3://policy-configs/prod/policyaware.yaml \
  --policy-sha256 expected-policy-sha256 \
  --policy-cache .policyaware/policy-cache.yaml \
  --require-auth
```

CI pull example:

```bash
policyaware policy pull \
  s3://policy-configs/prod/policyaware.yaml \
  --sha256 expected-policy-sha256 \
  --out policyaware.yaml \
  --force
```

## Signed Audit Traces

PolicyAware can add SHA256/HMAC integrity metadata to JSONL audit traces:

```bash
set POLICYAWARE_AUDIT_SIGNING_SECRET=replace-with-secret

policyaware up \
  --policy policyaware.yaml \
  --audit-signing-env POLICYAWARE_AUDIT_SIGNING_SECRET \
  --require-auth
```

Python:

```python
from policyaware import AuditLogger, Gateway, IntegritySigner

gateway = Gateway.from_policy_file("policyaware.yaml")
gateway.audit_logger = AuditLogger(
    ".policyaware/traces.jsonl",
    signer=IntegritySigner("replace-with-secret"),
)
```

Signed traces help compliance teams detect later tampering in exported audit evidence.

## Next Hardening Steps

For larger deployments, consider:

- Redis/Postgres-backed session state
- policy rollout and canary comparison
- centralized trace viewer
- service mesh mTLS
- immutable object storage for signed audit bundles
- SIEM/GRC export of emergency revoke activity

