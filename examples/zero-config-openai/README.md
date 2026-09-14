# Zero-Config OpenAI Example

This is the smallest raw-client pattern most developers look for first:

1. Load a deny-by-default YAML policy.
2. Call `gateway.inspect_and_mutate(...)` before OpenAI.
3. Receive a safe prompt plus structured metadata.
4. Call the raw OpenAI client only after PolicyAware allows the request.

```python
import policyaware
from openai import OpenAI

gateway = policyaware.Gateway.from_policy_file("policy.yaml")
client = OpenAI()
user_context = {"user_role": "billing_admin", "session_id": "99x-delta", "risk": "low"}
safe_prompt, token_meta = gateway.inspect_and_mutate(
    prompt="Email jane@example.com about claim ACME-42.",
    context=user_context,
    app="zero-config",
)
print(token_meta["decision"], token_meta["actions"])
response = client.responses.create(model="gpt-4.1-mini", input=safe_prompt)
print(response.output_text)
```

## Install

```bash
pip install policyaware openai
```

## Run

```bash
export OPENAI_API_KEY="..."
python app.py
```

On Windows PowerShell:

```powershell
$env:OPENAI_API_KEY="..."
python app.py
```

## What This Shows

- `policy.yaml` is deny-by-default.
- Secrets are blocked.
- Denied or approval-required requests fail closed with `PermissionError`.
- PII can be redacted before the prompt leaves your application.
- The raw OpenAI client remains unchanged; PolicyAware sits in front of it as a local governance preflight.
