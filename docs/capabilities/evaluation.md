# Evaluation

## What It Does

Evaluation verifies governance outcomes and model responses.

It supports:

- sensitive data leakage checks
- citation-required checks
- policy consistency checks
- golden dataset execution
- expected policy decision checks
- expected reason code checks

## Imports

```python
from policyaware import RuntimeEvaluator, EvalSuiteRunner
```

## Main APIs

| API | Type | What It Does |
| --- | --- | --- |
| `RuntimeEvaluator().evaluate(...)` | method | Runs runtime response checks such as leakage and citation checks. |
| `EvalSuiteRunner().run_file(path, gateway)` | method | Runs golden dataset cases against a gateway. |
| `policyaware eval run <suite>` | CLI | Executes an eval suite from the command line. |

## `EvalResult` Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | `str` | Evaluation check name. |
| `passed` | `bool` | True when the check passed. |
| `score` | `float` | Numeric score for the check. |
| `reason` | `str` | Human-readable result reason. |
| `severity` | `str` | Severity: `info`, `low`, `medium`, `high`, or `critical`. |

## `EvalReport` Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `suite` | `str` | Eval suite name. |
| `run_id` | `str` | Generated eval run identifier. |
| `cases` | `int` | Number of cases executed. |
| `passed` | `int` | Number of passing cases. |
| `failed` | `int` | Number of failing cases. |
| `policy_compliance_score` | `float` | Policy compliance score across cases. |
| `safety_score` | `float` | Safety score across cases. |
| `results` | `list[EvalCaseResult]` | Per-case results and reason codes. |

## Eval Case YAML Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | `str` | Stable eval case identifier. |
| `input` | `str` | Prompt or request text. |
| `user` | `dict` | User identity and role for the case. |
| `context` | `dict` | Region, risk, task type, domain, and other context. |
| `expected.decision` | `str` | Expected policy decision. |
| `expected.reason_codes` | `list[str]` | Expected reason codes that should appear. |

## Runtime Evaluation

```python
from policyaware import RuntimeEvaluator, GatewayRequest, PolicyDecision
from policyaware.models import Decision

request = GatewayRequest(
    tenant="acme",
    app="rag",
    context={"require_citations": True},
)
policy = PolicyDecision(decision=Decision.ALLOW, reason="Allowed")

results = RuntimeEvaluator().evaluate(
    request=request,
    response_text="The answer is supported by source [1].",
    policy=policy,
)

for result in results:
    print(result.name, result.passed, result.score)
```

## Golden Dataset Eval

```python
from policyaware import EvalSuiteRunner, Gateway

gateway = Gateway.from_policy_file("examples/policies/basic.yaml")

result = EvalSuiteRunner().run_file(
    "examples/evals/executable_governance_cases.yaml",
    gateway=gateway,
)

print(result["report"]["cases"])
print(result["report"]["failed"])
```

## CLI

```bash
policyaware eval run examples/evals/executable_governance_cases.yaml \
  --policy-file examples/policies/basic.yaml
```

## Eval Case Example

```yaml
cases:
  - id: pii_is_redacted
    input: "Email jane@example.com about the claim."
    user:
      id: eval_user
      role: support_agent
    context:
      region: us
      risk: low
      task_type: support
    expected:
      decision: conditional_allow
      reason_codes:
        - DATA.PII_DETECTED
        - POLICY.TRANSFORM_APPLIED
```
