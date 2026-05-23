# Provider Routing By Risk

Route low-risk requests to low-cost models and higher-risk requests to approved, higher-quality models.

## Install

```bash
pip install policyaware
```

## Run

```bash
python routing_demo.py
```

Expected output:

```text
public_safe route=external/low-cost decision=allow risk=low
sensitive_healthcare route=internal/approved decision=conditional_allow risk=high
secret_request route=none decision=deny risk=medium
```

See [terminal-output.txt](terminal-output.txt) for a captured run.

## What This Shows

- Policy decides whether a request can execute.
- Router chooses a compliant model after policy allows execution.
- PII/PHI increases risk and can trigger redaction.
- Secrets are denied before model routing.
