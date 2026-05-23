# PII Redaction Policy

Detect and redact emails, phone numbers, SSNs, credit cards, PHI-style patterns, and secrets before a prompt reaches a model.

## Install

```bash
pip install policyaware
```

## Run

```bash
python demo.py
```

Expected output:

```text
contains_pii=True
categories=email, phone
redacted=Contact [REDACTED_EMAIL] or [REDACTED_PHONE] about claim ACME-42.
gateway_decision=conditional_allow
gateway_actions=redact
```

See [terminal-output.txt](terminal-output.txt) for a captured run.

## What This Shows

- Direct string inspection with `DataProtectionEngine`.
- Redaction before model execution.
- YAML policy that conditionally allows PII only after redaction.
- A local simulated provider, so no LLM API key is required.

