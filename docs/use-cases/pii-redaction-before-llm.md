# PII Redaction Before LLM Calls

PolicyAware can inspect and redact PII, PHI, secrets, API keys, phone numbers, emails, addresses, credentials, and sensitive business text before a prompt leaves your application boundary.

This page is for searches like redact PII secrets before prompt leaves infrastructure, Python PII redaction for LLM prompts, and sensitive data protection for AI apps.

## Install

```bash
pip install policyaware
```

Optional stronger PII detection:

```bash
pip install "policyaware[privacy]"
python -m spacy download en_core_web_sm
```

## Simple String Check

```python
from policyaware import DataProtectionEngine

text = "Email jane@example.com or call 212-555-7890 about patient MRN 12345."

engine = DataProtectionEngine()
findings = engine.inspect(text)

print(findings.contains_pii)
print(findings.contains_phi)
print(findings.contains_secrets)
print(findings.categories)
print(engine.redact(text))
```

## Copy-Paste YAML

```yaml
name: pii-redaction-before-llm
version: 1
default_decision: deny

data_protection:
  redact_pii: true
  redact_phi: true
  redact_secrets: true
  block_on_secrets: true
  categories:
    - EMAIL_ADDRESS
    - PHONE_NUMBER
    - US_SSN
    - CREDIT_CARD
    - API_KEY
    - PASSWORD

rules:
  - id: allow-redacted-internal-support
    effect: allow
    when:
      role_in: ["support_agent", "admin"]
      data_sensitivity_in: ["public", "internal"]

  - id: require-approval-for-sensitive-regulated-data
    effect: require_approval
    when:
      domain_in: ["healthcare", "finance"]
      data_sensitivity_in: ["confidential", "restricted"]
```

## Gateway Example

```python
from policyaware import Gateway, GatewayRequest

gateway = Gateway.from_policy_file("policyaware.yaml")

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="support-copilot",
        user={"id": "u_123", "role": "support_agent"},
        context={"region": "us", "task_type": "support_response", "risk": "medium"},
        messages=[
            {
                "role": "user",
                "content": "Reply to jane@example.com about invoice card 4111-1111-1111-1111.",
            }
        ],
    )
)

print(response.policy.decision)
print(response.redacted_messages)
print(response.audit_trace)
```

## What It Detects

| Category | Examples |
| --- | --- |
| Global entities | Person, location, date/time, email, phone, URL, IP address |
| Financial entities | Credit card, IBAN, US bank number |
| Government IDs | US SSN, passport, driver's license, UK NHS, Indian PAN, Aadhaar |
| Secrets | API keys, tokens, passwords, private keys |
| PHI hints | Diagnosis, patient, MRN, prescription, clinical text |

## FAQ

### Is DataProtectionEngine ML-based?

The default engine is lightweight and rules-based. Optional Presidio integration can add stronger NLP-assisted entity recognition.

### Should I always redact?

For prompts leaving your infrastructure, redaction is usually the safer default. Some regulated internal workflows may require approval instead of automatic sending.
