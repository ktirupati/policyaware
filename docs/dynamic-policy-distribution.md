# Dynamic Policy Distribution

YAML policies work well as policy-as-code, but large organizations often need a way to distribute emergency policy changes without waiting for every application deployment.

PolicyAware supports dynamic policy sources so applications and sidecars can load policies from a local file, central HTTP(S) location, AWS S3, Google Cloud Storage, or ADLS Gen2 path, refresh them on an interval, cache the last known-good version, and fail closed when required.

For multi-layer enterprise stacks, combine dynamic policy distribution with
[policy composition](policy-composition.md). Composition defines predictable
hierarchy and override behavior across global, compliance, region, tenant, app,
and local policy layers. Explicit deny rules remain deny-first, and local
broadening exceptions must be time-bound and auditable.

## When To Use This

Use dynamic policy distribution when you have:

- many agents or services
- multiple production environments
- emergency permission revocation requirements
- compliance teams that need faster policy updates than code deployments
- central artifact storage or internal configuration services
- cloud storage policy artifacts such as AWS S3, Google Cloud Storage, or ADLS Gen2

## Sidecar With Central Policy URL

```bash
set POLICYAWARE_SIDECAR_TOKEN=replace-with-sidecar-token
set POLICYAWARE_POLICY_TOKEN=replace-with-policy-source-token

policyaware up \
  --policy-url https://policy.internal.example.com/policyaware.yaml \
  --tool-policy tool-governance.yaml \
  --policy-refresh-seconds 30 \
  --policy-timeout-seconds 5 \
  --policy-retry-base-seconds 1 \
  --policy-retry-max-seconds 60 \
  --policy-retry-jitter-seconds 0.25 \
  --policy-cache .policyaware/policy-cache.yaml \
  --fallback-policy examples/policies/emergency-fallback-deny.yaml \
  --require-auth
```

## AWS S3 Central Policy Source

Install the optional provider extra:

```bash
pip install "policyaware[providers]"
```

Use an S3 URI:

```bash
policyaware up \
  --policy-url s3://policy-configs/prod/policyaware.yaml \
  --policy-refresh-seconds 30 \
  --policy-cache .policyaware/policy-cache.yaml \
  --require-auth
```

PolicyAware uses the normal AWS credential chain used by `boto3`, such as environment variables, instance profile, ECS task role, EKS IRSA, SSO, or shared credentials.

## Google Cloud Storage Central Policy Source

Install the optional GCP extra:

```bash
pip install "policyaware[gcp]"
```

Use a GCS URI:

```bash
policyaware up \
  --policy-url gs://policy-configs/prod/policyaware.yaml \
  --policy-refresh-seconds 30 \
  --policy-cache .policyaware/policy-cache.yaml \
  --require-auth
```

PolicyAware uses the normal Google Application Default Credentials flow used by `google-cloud-storage`.

## ADLS Gen2 Central Policy Source

Install the optional Azure extra:

```bash
pip install "policyaware[azure]"
```

Use an ADLS Gen2 URI:

```bash
set POLICYAWARE_POLICY_TOKEN=replace-with-sas-token-if-needed

policyaware up \
  --policy-url abfss://policy-configs@acmeai.dfs.core.windows.net/prod/policyaware.yaml \
  --policy-refresh-seconds 30 \
  --policy-cache .policyaware/policy-cache.yaml \
  --require-auth
```

Python SDK:

```python
from policyaware import Gateway

gateway = Gateway.from_policy_source(
    "abfss://policy-configs@acmeai.dfs.core.windows.net/prod/policyaware.yaml",
    refresh_seconds=30,
    timeout_seconds=5,
    cache_file=".policyaware/policy-cache.yaml",
    fallback_policy_file="examples/policies/emergency-fallback-deny.yaml",
    auth_token="replace-with-sas-token-if-needed",
    fail_closed=True,
    retry_base_seconds=1,
    retry_max_seconds=60,
    retry_jitter_seconds=0.25,
)
```

If `auth_token` is not provided, PolicyAware uses Azure `DefaultAzureCredential`, which works with managed identity, Azure CLI login, workload identity, or environment-based credentials depending on your runtime.

Behavior:

- the sidecar fetches the central policy before serving requests
- every request can trigger a refresh after the configured TTL
- HTTP, S3, GCS, and ADLS fetches use a strict timeout
- failed refreshes use exponential backoff with jitter to reduce retry storms
- the policy is schema-validated before becoming active
- refreshed policies are built first and then atomically swapped into the active in-memory engine
- the last known-good policy can be cached locally
- a restrictive local fallback policy can be used during cold-start outages
- default behavior is fail-closed if refresh fails before a policy is loaded

## Python SDK With Dynamic Source

```python
from policyaware import Gateway

gateway = Gateway.from_policy_source(
    "https://policy.internal.example.com/policyaware.yaml",
    refresh_seconds=30,
    timeout_seconds=5,
    cache_file=".policyaware/policy-cache.yaml",
    fallback_policy_file="examples/policies/emergency-fallback-deny.yaml",
    auth_token="replace-with-policy-source-token",
    fail_closed=True,
    retry_base_seconds=1,
    retry_max_seconds=60,
    retry_jitter_seconds=0.25,
)
```

The rest of your application can continue using normal `Gateway.chat(...)`.

## Thread-Safe Refresh Behavior

Dynamic policy refreshes do not mutate the active policy engine in place.
PolicyAware loads the source, validates the YAML, constructs a new `PolicyEngine`,
and then swaps the active snapshot and engine under a lock.

This means an in-flight request uses one complete policy engine object. It does
not mix rules from the old policy and the new policy during refresh.

The swap also avoids long-lived references from audit or telemetry paths back to
old policy engines. Audit traces and runtime telemetry store serialized request,
response, decision, reason-code, and matched-rule fields. They do not retain the
previous `PolicyEngine` object, so after in-flight requests finish, Python can
garbage-collect the old parsed policy.

## Timeout And Retry-Storm Protection

Remote policy distribution should not turn a slow policy endpoint into an
internal outage. PolicyAware protects dynamic refreshes with:

- strict fetch timeout, default `5` seconds
- refresh TTL, default `60` seconds
- exponential backoff after failed refreshes
- jitter to avoid synchronized retries across many replicas
- last known-good cache
- restrictive emergency fallback policy
- fail-closed behavior when no valid policy can be loaded

Recommended sidecar settings:

```bash
policyaware up \
  --policy-url https://policy.internal.example.com/policyaware.yaml \
  --policy-refresh-seconds 30 \
  --policy-timeout-seconds 5 \
  --policy-retry-base-seconds 1 \
  --policy-retry-max-seconds 60 \
  --policy-retry-jitter-seconds 0.25 \
  --policy-cache .policyaware/policy-cache.yaml \
  --fallback-policy examples/policies/emergency-fallback-deny.yaml \
  --require-auth
```

If a refresh fails, PolicyAware does not immediately retry on every request. It
schedules the next attempt using exponential backoff and jitter, while continuing
to use the active policy when one is already loaded. In fail-closed mode, if no
valid policy exists, requests are denied rather than running without governance.

## Pull A Policy In CI/CD

```bash
policyaware policy pull \
  https://policy.internal.example.com/policyaware.yaml \
  --out policyaware.yaml \
  --cache .policyaware/policy-cache.yaml \
  --force

policyaware policy validate policyaware.yaml
policyaware contract check ./src --policy tool-governance.yaml --fail-on high
policyaware scan ./src --fail-on high
```

ADLS Gen2 pull:

```bash
policyaware policy pull \
  abfss://policy-configs@acmeai.dfs.core.windows.net/prod/policyaware.yaml \
  --out policyaware.yaml \
  --cache .policyaware/policy-cache.yaml \
  --force
```

S3 pull:

```bash
policyaware policy pull \
  s3://policy-configs/prod/policyaware.yaml \
  --out policyaware.yaml \
  --cache .policyaware/policy-cache.yaml \
  --force
```

GCS pull:

```bash
policyaware policy pull \
  gs://policy-configs/prod/policyaware.yaml \
  --out policyaware.yaml \
  --cache .policyaware/policy-cache.yaml \
  --force
```

## Emergency Revoke Pattern

1. Compliance updates the central policy artifact.
2. The central policy source serves a new YAML version.
3. Sidecars refresh automatically based on `--policy-refresh-seconds`.
4. New requests are denied, redacted, routed differently, or escalated based on the updated policy.
5. Audit traces show the active policy decision and matched rules.

Example emergency rule:

```yaml
default: deny
rules:
  - name: emergency_disable_customer_write_actions
    effect: deny
    when:
      request.action_type_in:
        - write
        - delete
      request.domain: customer_data

  - name: allow_read_only_support
    effect: allow
    when:
      user.role: support_agent
      request.action_type: read
```

## Fail-Closed vs Fail-Open

Default recommendation:

```bash
policyaware up \
  --policy-url https://policy.internal.example.com/policyaware.yaml \
  --policy-cache .policyaware/policy-cache.yaml \
  --fallback-policy examples/policies/emergency-fallback-deny.yaml \
  --require-auth
```

This startup order is:

```text
remote source -> last known-good cache -> local emergency fallback -> fail closed
```

The fallback policy should be highly restrictive. A safe starter example is:

```yaml
id: emergency_fallback_deny_policy
schema_version: "0.4"
default: deny

rules:
  - name: deny_all_when_remote_policy_unavailable
    effect: deny
    when: {}
```

This prevents a container cold start from running without governance when S3,
GCS, ADLS Gen2, HTTP policy storage, or the network is temporarily unavailable.

For availability-first internal environments, use:

```bash
policyaware up \
  --policy-url https://policy.internal.example.com/policyaware.yaml \
  --policy-cache .policyaware/policy-cache.yaml \
  --fallback-policy examples/policies/emergency-fallback-deny.yaml \
  --fail-open
```

Fail-open means PolicyAware keeps using the last loaded policy if a later refresh fails. It does not mean requests bypass policy checks.

## Checksum Pinning

Use `--policy-sha256` to reject stale, downgraded, or tampered policy artifacts:

```bash
policyaware up \
  --policy-url s3://policy-configs/prod/policyaware.yaml \
  --policy-sha256 expected-policy-sha256 \
  --policy-cache .policyaware/policy-cache.yaml \
  --require-auth
```

The same pin can be used with `policy pull`:

```bash
policyaware policy pull \
  gs://policy-configs/prod/policyaware.yaml \
  --sha256 expected-policy-sha256 \
  --out policyaware.yaml \
  --force
```

If a remote policy fails checksum validation, PolicyAware rejects the downloaded
policy, emits a `CRITICAL` log on the `policyaware.policy_source` logger, and
attempts to use the last known-good cache. The invalid policy is not written to
the cache. If no valid cached policy or fallback policy exists, the dynamic
engine fails closed instead of running without governance.

## What This Does Not Provide

This feature is intentionally lightweight. It does not provide a fully managed admin UI, click-to-revoke dashboard, policy approval portal, or multi-region policy database.

It gives maintainers and enterprises a practical bridge:

- keep policy-as-code
- distribute policies centrally
- refresh running sidecars
- cache last known-good policy
- fail closed by default
- avoid redeploying every agent for every policy change
