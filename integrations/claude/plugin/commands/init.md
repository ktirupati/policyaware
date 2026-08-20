# /policyaware:init

Initialize PolicyAware policy-as-code files for the current repository.

## Purpose

Use this command when the repository has LLM, RAG, MCP/tool, or agent code but does not yet have a `policyaware.yaml` baseline.

## Command

```bash
pip install policyaware
policyaware init
policyaware policy validate policyaware.yaml
```

## Starter Policy Shape

If Claude needs to create the policy manually, start deny-by-default:

```yaml
name: policyaware-baseline
version: 1
default_decision: deny

data_protection:
  redact_pii: true
  redact_phi: true
  redact_secrets: true

rules:
  - id: allow-low-risk-internal
    effect: allow
    when:
      risk_in: ["low"]
      data_sensitivity_in: ["public", "internal"]

  - id: require-approval-for-regulated
    effect: require_approval
    when:
      domain_in: ["healthcare", "finance", "legal"]
```

## Expected Claude Behavior

1. Check for existing `policyaware.yaml`.
2. Preserve existing user policy files.
3. Create a conservative baseline only if missing.
4. Validate the policy.
5. Recommend `policyaware scan . --format html,json,sarif,markdown`.
6. Offer to add `.github/workflows/policyaware-scan.yml`.
