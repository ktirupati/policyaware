# Centralized AI Policy Distribution

PolicyAware supports centralized YAML policy distribution from local files, HTTP endpoints, AWS S3, Google Cloud Storage, Azure ADLS Gen2, and other object-store style paths through policy sources.

This page is for searches like centralized YAML policy distribution S3 GCS, cryptographically pinned remote compliance policy, and fail-closed LLM security gateway architecture.

## Install

```bash
pip install policyaware
```

## Remote Policy Startup

```bash
policyaware up \
  --policy-url s3://company-ai-policies/prod/policyaware.yaml \
  --policy-cache .policyaware/policy-cache.yaml \
  --fallback-policy examples/policies/emergency-fallback-deny.yaml \
  --policy-timeout-seconds 5 \
  --policy-refresh-seconds 60 \
  --require-auth
```

## Python Example

```python
from policyaware import Gateway
from policyaware.policy_sources import FallbackPolicySource, HttpPolicySource

source = FallbackPolicySource(
    primary=HttpPolicySource(
        "https://policies.example.com/policyaware.yaml",
        timeout_seconds=5,
        checksum_sha256="expected_sha256_hash_here",
    ),
    fallback_file="examples/policies/emergency-fallback-deny.yaml",
    cache_file=".policyaware/policy-cache.yaml",
)

gateway = Gateway.from_policy_source(source)
```

## Emergency Fallback Policy

```yaml
name: emergency-fallback-deny
version: 1
default_decision: deny

rules:
  - id: deny-all-when-central-policy-unavailable
    effect: deny
    when:
      always: true
```

## Reliability Behavior

| Risk | PolicyAware Behavior |
| --- | --- |
| Remote policy unavailable | Use last known-good cache or emergency fallback |
| Remote checksum mismatch | Log critical event and keep previous valid policy |
| Slow policy server | Strict timeout prevents hung startup |
| Retry storm risk | Exponential backoff and jitter |
| Background refresh race | Atomic policy swap |

## Recommended Enterprise Pattern

1. Store global policies in S3, GCS, ADLS Gen2, or an internal HTTPS endpoint.
2. Validate policy changes in CI before upload.
3. Pin critical production policies with SHA-256 checksums.
4. Configure a local emergency fallback policy.
5. Refresh on an explicit internal interval.
6. Export policy load failures to OpenTelemetry or central logs.

## Related Documentation

- [Dynamic Policy Distribution](../dynamic-policy-distribution.md)
- [Enterprise Hardening](../enterprise-hardening.md)
- [Policy Composition](../policy-composition.md)
- [Security Boundaries](../security-boundaries.md)
