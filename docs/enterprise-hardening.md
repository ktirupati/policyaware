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

If checksum validation fails during remote refresh, PolicyAware logs a
`CRITICAL` event through `policyaware.policy_source`, rejects the downloaded
policy, and attempts the last known-good cache. Failed checksum downloads do not
overwrite the cache. If no valid cached or fallback policy exists, enforcement
fails closed.

## Cold-Start Fallback Policy

For dynamic policy sources, combine remote policy loading with a last known-good
cache and a restrictive local fallback policy:

```bash
policyaware up \
  --policy-url s3://policy-configs/prod/policyaware.yaml \
  --policy-sha256 expected-policy-sha256 \
  --policy-cache .policyaware/policy-cache.yaml \
  --policy-timeout-seconds 5 \
  --policy-retry-base-seconds 1 \
  --policy-retry-max-seconds 60 \
  --policy-retry-jitter-seconds 0.25 \
  --fallback-policy examples/policies/emergency-fallback-deny.yaml \
  --require-auth
```

Startup order:

```text
remote source -> last known-good cache -> local emergency fallback -> fail closed
```

Use this when containers may start during a cloud storage, DNS, or network
outage. The bundled fallback policy is intentionally restrictive and denies all
requests unless you replace it with your own emergency-safe policy.

Remote refreshes use strict timeouts plus exponential backoff with jitter so
many service replicas do not retry a slow central policy source in lockstep.

Dynamic refreshes atomically replace the active policy engine instead of
mutating it in place. Audit and telemetry paths store serialized decisions and
trace fields, not references to old `PolicyEngine` objects. Once in-flight
requests finish, old parsed policies are eligible for normal Python garbage
collection.

## Blocked Action Handshake

When a request is denied or requires approval, preserve PolicyAware's structured
rejection payload across your API boundary. Do not convert it into an opaque
exception string.

```python
from policyaware import Gateway, GatewayRequest, policy_rejection

gateway = Gateway.from_policy_file("policyaware.yaml")
response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="support-api",
        user={"role": "support_agent"},
        context={"region": "us", "risk": "low"},
        messages=[{"role": "user", "content": "Use secret_api_key_abcdefghijklmnop"}],
    )
)

rejection = policy_rejection(response)
if rejection:
    # Return this to the API caller and send it to tracing/SIEM.
    print(rejection.model_dump(mode="json"))
```

The rejection payload includes `decision`, `reason`, `reason_codes`,
`matched_rules`, `trace_id`, `risk_tier`, approval status, and remediation. The
runtime telemetry collector also emits `policyaware.blocked`,
`policyaware.reason_codes`, and `policyaware.matched_rules` attributes so
distributed dashboards can alert on enforcement activity.

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
