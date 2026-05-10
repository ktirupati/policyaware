from policyaware.data_protection import DataProtectionEngine
from policyaware.models import Decision, GatewayRequest
from policyaware.policy import PolicyEngine


def test_deny_by_default_when_no_allow_matches() -> None:
    engine = PolicyEngine({"default": "deny", "rules": []})
    decision = engine.decide(
        GatewayRequest(
            tenant="acme",
            app="test",
            user={"role": "unknown"},
            context={"risk": "low"},
            messages=[{"role": "user", "content": "hello"}],
        ),
        DataProtectionEngine().inspect("hello"),
    )

    assert decision.decision == Decision.DENY


def test_transform_redacts_pii_for_non_privileged_user() -> None:
    engine = PolicyEngine(
        {
            "default": "deny",
            "rules": [
                {
                    "name": "allow_support",
                    "effect": "allow",
                    "when": {"user.role": "support"},
                },
                {
                    "name": "redact_pii",
                    "effect": "transform",
                    "action": "redact",
                    "when": {"data.contains_pii": True},
                },
            ],
        }
    )
    findings = DataProtectionEngine().inspect("email jane@example.com")
    decision = engine.decide(
        GatewayRequest(tenant="acme", app="test", user={"role": "support"}),
        findings,
    )

    assert decision.decision == Decision.CONDITIONAL_ALLOW
    assert decision.actions == ["redact"]
    assert decision.explanation is not None
