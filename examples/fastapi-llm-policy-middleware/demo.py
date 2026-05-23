from __future__ import annotations

from pathlib import Path

from policyaware import Gateway, GatewayRequest


gateway = Gateway.from_policy_file(Path(__file__).with_name("policy.yaml"))

cases = {
    "allowed_support_request": "Summarize claim ACME-42.",
    "pii_redaction_request": "Email jane@example.com about claim ACME-42.",
    "secret_leak_request": "Use api_key_abcdefghijklmnop123456 for this request.",
}

for name, prompt in cases.items():
    response = gateway.chat(
        GatewayRequest(
            tenant="acme",
            app="fastapi-llm-policy-middleware",
            user={"id": "demo_user", "role": "support_agent"},
            context={"region": "us", "task_type": "support_chat", "risk": "low"},
            messages=[{"role": "user", "content": prompt}],
        )
    )
    print(f"{name}: {response.policy.decision.value}")

