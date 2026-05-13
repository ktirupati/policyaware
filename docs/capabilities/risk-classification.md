# Risk Classification

## What It Does

`RiskClassifier` assigns a request to:

- `low`
- `medium`
- `high`
- `critical`

The score is deterministic and based on context plus detected data.

## Import

```python
from policyaware import RiskClassifier
```

## Main APIs

| API | Type | What It Does |
| --- | --- | --- |
| `RiskClassifier()` | class | Creates the deterministic risk classifier. |
| `classifier.classify(request, findings)` | method | Produces a `RiskAssessment` from request context and data findings. |

## `RiskAssessment` Result Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `tier` | `RiskTier` | Risk tier: `low`, `medium`, `high`, or `critical`. |
| `score` | `float` | Numeric risk score. |
| `factors` | `list[str]` | Inputs that increased risk, such as `pii`, `phi`, `tool_use`, or `regulated_domain:healthcare`. |
| `reason_codes` | `list[str]` | Machine-readable codes explaining risk classification. |
| `fail_safe` | `str` | Default fail-safe behavior, usually `deny`. |

## Common Inputs

| Input Area | Example | Typical Impact |
| --- | --- | --- |
| Data sensitivity | PII, PHI, secrets | Raises risk and may trigger redaction or deny rules. |
| User role | `clinician`, `support_agent`, `intern` | Used by policy to permit, block, or require approval. |
| Regulated domain | `healthcare`, `finance`, `legal`, `hr` | Raises risk and can restrict provider/model choice. |
| Tool use | external connector or agent action | Raises risk because side effects may occur. |
| Autonomy | `assistive`, `agentic`, `autonomous` | Higher autonomy raises risk. |
| Business impact | `low`, `medium`, `high`, `critical` | Higher impact raises risk and approval requirements. |
| Action type | `read`, `write`, `delete`, `payment`, `deploy` | Write/delete/payment/deploy actions are treated as higher risk. |

## Example

```python
from policyaware import DataProtectionEngine, GatewayRequest, RiskClassifier

request = GatewayRequest(
    tenant="acme",
    app="clinical-assistant",
    user={"role": "clinician"},
    context={
        "domain": "healthcare",
        "autonomy": "assistive",
        "business_impact": "high",
        "action_type": "read",
    },
    messages=[{"role": "user", "content": "Patient diagnosis: diabetes"}],
)

findings = DataProtectionEngine().inspect(request.prompt_text)
risk = RiskClassifier().classify(request, findings)

print(risk.tier.value)
print(risk.score)
print(risk.factors)
print(risk.reason_codes)
```

## Inputs That Increase Risk

- PII
- PHI
- secrets
- regulated domains such as healthcare, finance, legal, HR
- tool use
- autonomous or agentic workflows
- high business impact
- write/delete/deploy/payment actions
- declared high or critical risk

## YAML Use

```yaml
rules:
  - name: require_approval_for_high_risk
    effect: require_approval
    when:
      risk.tier_in:
        - high
        - critical
```
