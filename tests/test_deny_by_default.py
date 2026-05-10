from policyaware.data_protection import DataProtectionEngine
from policyaware.models import Decision, GatewayRequest
from policyaware.policy import PolicyEngine


def test_transform_rule_does_not_grant_access_without_allow() -> None:
    engine = PolicyEngine(
        {
            "default": "deny",
            "rules": [
                {
                    "name": "redact_pii",
                    "effect": "transform",
                    "action": "redact",
                    "when": {"data.contains_pii": True},
                }
            ],
        }
    )
    findings = DataProtectionEngine().inspect("email jane@example.com")
    decision = engine.decide(
        GatewayRequest(tenant="acme", app="test", user={"role": "unknown"}),
        findings,
    )

    assert decision.decision == Decision.DENY

