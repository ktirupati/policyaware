# FastAPI LLM Policy Middleware

Add deny-by-default policy checks, PII redaction, risk scoring, and audit traces in front of a FastAPI LLM endpoint.

## Install

```bash
pip install policyaware fastapi uvicorn
```

## Run Without A Server

Use the included local demo when you only want to verify the policy behavior:

```bash
python demo.py
```

Expected output:

```text
allowed_support_request: allow
pii_redaction_request: conditional_allow
secret_leak_request: deny
```

See [terminal-output.txt](terminal-output.txt) for a captured run.

## Run The FastAPI App

```bash
uvicorn app:app --reload
```

Send a request from another terminal:

```python
import requests

response = requests.post(
    "http://127.0.0.1:8000/chat",
    json={
        "prompt": "Email jane@example.com about claim ACME-42",
        "role": "support_agent",
    },
)

print(response.json())
```

## What This Shows

- FastAPI request body becomes a `GatewayRequest`.
- `policy.yaml` decides allow, deny, or redact.
- PII is detected before model execution.
- The local simulated provider returns deterministic output, so no model API key is required.
