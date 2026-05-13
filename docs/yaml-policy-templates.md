# YAML Policy Templates

This page is a convenient root-level entry point for copy/paste YAML policies.

See the full template guide:

[Ready-To-Use YAML Policies](capabilities/ready-to-use-yaml.md)

## Basic Enterprise Policy

Save as `basic-enterprise.yaml`.

```yaml
id: basic_enterprise_policy
schema_version: "0.2"
default: deny

rules:
  - name: deny_secret_leakage
    effect: deny
    when:
      data.contains_secrets: true

  - name: redact_pii_for_standard_users
    effect: transform
    action: redact
    when:
      data.contains_pii: true
      user.role_not_in:
        - privacy_admin
        - compliance_officer

  - name: allow_enterprise_users_low_medium_risk
    effect: allow
    when:
      user.role_in:
        - support_agent
        - support_manager
        - developer
        - analyst
        - privacy_admin
      request.region: us
      risk.tier_in:
        - low
        - medium

  - name: require_approval_for_high_or_critical_risk
    effect: require_approval
    when:
      risk.tier_in:
        - high
        - critical
```

## Test

```bash
policyaware policy validate basic-enterprise.yaml
policyaware policy explain basic-enterprise.yaml --prompt "Email jane@example.com about the ticket."
```

The full guide also includes:

- support copilot YAML
- healthcare / PHI YAML
- code assistant YAML
- ML-assisted governance YAML
- agent tool governance YAML
- golden eval suite YAML
- provider routing YAML

