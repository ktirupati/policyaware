# Data Protection

## What It Does

Data protection detects and redacts sensitive content before requests reach a model or tool.

It covers:

- PII: email, phone, SSN, credit card
- PHI-style patterns: medical record, patient ID, diagnosis, medication
- Secrets: API keys, bearer tokens
- Optional ML/NLP PII signals through Presidio

## When To Use It

Use this when you want to inspect a plain string, redact a prompt, or make policy decisions based on sensitive data.

## Import

```python
from policyaware import DataProtectionEngine
```

## Main APIs

| API | Type | What It Does |
| --- | --- | --- |
| `DataProtectionEngine()` | class | Creates the built-in rules-based sensitive-data detector. |
| `engine.inspect(text)` | method | Detects sensitive data and returns a `DataFindings` result. |
| `engine.redact(text)` | method | Detects sensitive data and returns redacted text in `redacted_text`. |
| `PresidioPIIClassifier` | optional ML class | Adds Microsoft Presidio-based PII/NLP detection when installed. |

## `DataFindings` Result Fields

`engine.inspect(text)` and `engine.redact(text)` return a `DataFindings` object.

| Field | Type | Meaning |
| --- | --- | --- |
| `contains_pii` | `bool` | True when PII such as email, phone, SSN, or credit card is detected. |
| `contains_phi` | `bool` | True when PHI-style data such as medical record, patient ID, diagnosis, or medication is detected. |
| `contains_secrets` | `bool` | True when secrets such as API keys or bearer tokens are detected. |
| `contains_sensitive` | `bool` | True when any PII, PHI, or secret is detected. |
| `categories` | `list[str]` | Detected categories, such as `email`, `phone`, `ssn`, `api_key`, or `diagnosis`. |
| `redactions` | `int` | Number of detected matches. |
| `redacted_text` | `str \| None` | Redacted text when using `engine.redact(text)`. |

## String Inspection

```python
from policyaware import DataProtectionEngine

text = "Email jane@example.com or call 212-555-7890."

engine = DataProtectionEngine()
findings = engine.inspect(text)

print(findings.contains_pii)
print(findings.contains_phi)
print(findings.contains_secrets)
print(findings.categories)
```

Expected:

```text
True
False
False
['email', 'phone']
```

## Redaction

```python
redacted = engine.redact(text)
print(redacted.redacted_text)
```

Expected:

```text
Email [REDACTED_EMAIL] or call [REDACTED_PHONE].
```

## Policy Fields

Data findings are exposed to YAML:

```yaml
rules:
  - name: deny_secrets
    effect: deny
    when:
      data.contains_secrets: true

  - name: redact_pii
    effect: transform
    action: redact
    when:
      data.contains_pii: true
```

## Optional Presidio PII

Install:

```bash
pip install "policyaware[presidio]"
```

Example:

```python
from policyaware import PresidioPIIClassifier

classifier = PresidioPIIClassifier(score_threshold=0.5)
assessment = classifier.classify(
    "Krishna Kishor lives at 120 Main Street and his phone is 212-555-7890."
)

print(assessment.model_dump())
```

Use Presidio when you need stronger detection of names, locations, and addresses.
