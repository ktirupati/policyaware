from __future__ import annotations

from pathlib import Path

from policyaware import DataProtectionEngine, Gateway, GatewayRequest


text = "Contact jane@example.com or 212-555-7890 about claim ACME-42."
engine = DataProtectionEngine()
findings = engine.redact(text)

print(f"contains_pii={findings.contains_pii}")
print(f"categories={', '.join(findings.categories)}")
print(f"redacted={findings.redacted_text}")

gateway = Gateway.from_policy_file(Path(__file__).with_name("policy.yaml"))
response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="pii-redaction-policy",
        user={"id": "support_1", "role": "support_agent"},
        context={"region": "us", "task_type": "support_summary", "risk": "low"},
        messages=[{"role": "user", "content": text}],
    )
)

print(f"gateway_decision={response.policy.decision.value}")
print(f"gateway_actions={', '.join(response.policy.actions)}")

