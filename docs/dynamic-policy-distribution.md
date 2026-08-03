# Dynamic Policy Distribution

YAML policies work well as policy-as-code, but large organizations often need a way to distribute emergency policy changes without waiting for every application deployment.

PolicyAware supports dynamic policy sources so applications and sidecars can load policies from a local file, central HTTP(S) location, AWS S3, Google Cloud Storage, or ADLS Gen2 path, refresh them on an interval, cache the last known-good version, and fail closed when required.

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
  --policy-cache .policyaware/policy-cache.yaml \
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
    cache_file=".policyaware/policy-cache.yaml",
    auth_token="replace-with-sas-token-if-needed",
    fail_closed=True,
)
```

If `auth_token` is not provided, PolicyAware uses Azure `DefaultAzureCredential`, which works with managed identity, Azure CLI login, workload identity, or environment-based credentials depending on your runtime.

Behavior:

- the sidecar fetches the central policy before serving requests
- every request can trigger a refresh after the configured TTL
- the policy is schema-validated before becoming active
- the last known-good policy can be cached locally
- default behavior is fail-closed if refresh fails before a policy is loaded

## Python SDK With Dynamic Source

```python
from policyaware import Gateway

gateway = Gateway.from_policy_source(
    "https://policy.internal.example.com/policyaware.yaml",
    refresh_seconds=30,
    cache_file=".policyaware/policy-cache.yaml",
    auth_token="replace-with-policy-source-token",
    fail_closed=True,
)
```

The rest of your application can continue using normal `Gateway.chat(...)`.

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
policyaware up --policy-url https://policy.internal.example.com/policyaware.yaml --require-auth
```

This fails closed if no valid policy can be loaded.

For availability-first internal environments, use:

```bash
policyaware up \
  --policy-url https://policy.internal.example.com/policyaware.yaml \
  --policy-cache .policyaware/policy-cache.yaml \
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

## What This Does Not Provide

This feature is intentionally lightweight. It does not provide a fully managed admin UI, click-to-revoke dashboard, policy approval portal, or multi-region policy database.

It gives maintainers and enterprises a practical bridge:

- keep policy-as-code
- distribute policies centrally
- refresh running sidecars
- cache last known-good policy
- fail closed by default
- avoid redeploying every agent for every policy change
