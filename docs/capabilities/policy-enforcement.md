# Policy Enforcement

## What It Does

The policy engine applies YAML rules and returns one of four decisions:

- `allow`
- `deny`
- `conditional_allow`
- `require_approval`

PolicyAware is deny-by-default unless a rule explicitly allows the request.

## Imports

```python
from policyaware import PolicyEngine, PolicySchemaValidator
```

## Main APIs

| API | Type | What It Does |
| --- | --- | --- |
| `PolicyEngine.from_file(path)` | class method | Loads a YAML policy file into the policy engine. |
| `engine.decide(request, findings, risk=None, ml=None)` | method | Evaluates request context, data findings, risk, and ML signals against policy rules. |
| `PolicySchemaValidator().validate(policy)` | method | Validates policy structure before runtime use. |
| `policyaware policy validate <file>` | CLI | Validates a YAML policy file from the command line. |
| `policyaware policy explain <file>` | CLI | Shows the decision, reason codes, and matched rules for a sample request. |

## `PolicyDecision` Result Fields

`engine.decide(...)` returns a `PolicyDecision` object.

| Field | Type | Meaning |
| --- | --- | --- |
| `decision` | `Decision` | Final result: `allow`, `deny`, `conditional_allow`, or `require_approval`. |
| `actions` | `list[str]` | Transform or enforcement actions, such as `redact`. |
| `matched_rules` | `list[str]` | Policy rule names that matched the request. |
| `violated_rules` | `list[str]` | Policy rules that were violated. |
| `reason` | `str` | Human-readable decision explanation. |
| `reason_codes` | `list[str]` | Machine-readable reason codes for audit and automation. |
| `risk_score` | `float` | Risk score used during policy decisioning. |
| `risk_tier` | `RiskTier` | Risk tier: `low`, `medium`, `high`, or `critical`. |
| `remediation` | `list[str]` | Suggested fixes or next steps. |
| `explanation` | `DecisionExplanation \| None` | Structured explanation with summary, policy IDs, and remediation. |

## YAML Policy Context Fields

| Root | Example | Meaning |
| --- | --- | --- |
| `tenant` | `tenant: acme` | Tenant identifier. |
| `app` | `app: support-copilot` | Calling application. |
| `user` | `user.role_in: [support_agent]` | User attributes such as role, ID, or department. |
| `request` | `request.region: us` | Request context such as region, task type, domain, or autonomy. |
| `data` | `data.contains_pii: true` | Output from `DataProtectionEngine`. |
| `risk` | `risk.tier_in: [low, medium]` | Output from `RiskClassifier`. |
| `ml` | `ml.prompt_injection.detected: true` | Optional ML-assisted classifier signals. |

## YAML Example

```yaml
id: support_policy
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

  - name: allow_support_requests
    effect: allow
    when:
      user.role_in:
        - support_agent
        - support_manager
      request.region: us
      risk.tier_in:
        - low
        - medium
```

## Validate Policy

```python
import yaml
from policyaware import PolicySchemaValidator

with open("support_policy.yaml", "r", encoding="utf-8") as handle:
    policy = yaml.safe_load(handle)

PolicySchemaValidator().validate(policy)
```

CLI:

```bash
policyaware policy validate support_policy.yaml
```

## Decide In Python

```python
from policyaware import DataProtectionEngine, GatewayRequest, PolicyEngine

engine = PolicyEngine.from_file("support_policy.yaml")
request = GatewayRequest(
    tenant="acme",
    app="support",
    user={"role": "support_agent"},
    context={"region": "us", "risk": "low"},
    messages=[{"role": "user", "content": "Email jane@example.com"}],
)
findings = DataProtectionEngine().inspect(request.prompt_text)

decision = engine.decide(request, findings)
print(decision.decision.value)
print(decision.matched_rules)
print(decision.reason_codes)
```

## Supported Operators

```yaml
user.role: support_agent
user.role_in: [support_agent, support_manager]
user.role_not_in: [intern]
risk.score_gte: 0.7
risk.score_lte: 0.3
```

Supported roots:

```text
tenant, app, user, request, data, risk, ml
```
