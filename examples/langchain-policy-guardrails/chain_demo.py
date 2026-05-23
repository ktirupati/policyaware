from __future__ import annotations

from pathlib import Path

from policyaware import Gateway, GatewayRequest


gateway = Gateway.from_policy_file(Path(__file__).with_name("policy.yaml"))


def guarded_chain(prompt: str) -> tuple[bool, str, list[str]]:
    response = gateway.chat(
        GatewayRequest(
            tenant="acme",
            app="langchain-policy-guardrails",
            user={"id": "dev_1", "role": "developer"},
            context={"region": "us", "task_type": "chain", "risk": "low"},
            messages=[{"role": "user", "content": prompt}],
        )
    )
    model_called = bool(response.route)
    return model_called, response.policy.decision.value, response.policy.actions


cases = {
    "safe_prompt": "Summarize the incident report.",
    "pii_prompt": "Summarize this customer email: jane@example.com",
    "secret_prompt": "Use secret_token_abcdefghijklmnop123456 to call the API.",
}

for name, prompt in cases.items():
    model_called, decision, actions = guarded_chain(prompt)
    suffix = f" actions={','.join(actions)}" if actions else ""
    print(f"{name}: model_called={model_called} decision={decision}{suffix}")

