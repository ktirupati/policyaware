from __future__ import annotations

from policyaware import (
    DataFindings,
    GatewayRequest,
    PolicyComposer,
    PolicyEngine,
    PolicyLayer,
    RiskAssessment,
)
from policyaware.models import Decision, RiskTier
from policyaware.policy_composition import load_policy_layers


GLOBAL_POLICY = {
    "id": "global",
    "default": "deny",
    "rules": [
        {
            "name": "deny_phi_external",
            "effect": "deny",
            "when": {"data.contains_phi": True, "request.model_scope": "external"},
        }
    ],
}

APP_POLICY = {
    "id": "app",
    "default": "deny",
    "rules": [
        {
            "name": "allow_support",
            "effect": "allow",
            "when": {"user.role": "support_agent", "risk.tier": "low"},
        }
    ],
}

LOCAL_BROADENING = {
    "id": "local",
    "default": "deny",
    "rules": [
        {
            "name": "allow_phi_external",
            "effect": "allow",
            "when": {"data.contains_phi": True, "request.model_scope": "external"},
        }
    ],
}

LOCAL_SAFE = {
    "id": "local_safe",
    "default": "deny",
    "rules": [
        {
            "name": "allow_internal_research",
            "effect": "allow",
            "when": {
                "user.role": "researcher",
                "request.model_scope": "internal",
                "risk.tier": "low",
            },
        }
    ],
}


def test_higher_precedence_deny_blocks_lower_allow() -> None:
    report = PolicyComposer().compose(
        [
            PolicyLayer("local", "local_override", LOCAL_BROADENING),
            PolicyLayer("global", "global", GLOBAL_POLICY),
        ]
    )

    assert report.has_errors
    assert any(finding.code == "POLICY_COMPOSITION.DENY_OVERRIDE_BLOCKED" for finding in report.findings)
    assert all("allow_phi_external" not in rule["name"] for rule in report.composed_policy["rules"])


def test_safe_local_layer_composes_and_engine_denies_phi_external() -> None:
    report = PolicyComposer().compose(
        [
            PolicyLayer("global", "global", GLOBAL_POLICY),
            PolicyLayer("app", "app", APP_POLICY),
            PolicyLayer("local", "local_override", LOCAL_SAFE),
        ]
    )

    assert not report.has_errors
    engine = PolicyEngine(report.composed_policy)
    request = GatewayRequest(
        tenant="acme",
        app="claims",
        user={"role": "researcher"},
        context={"model_scope": "external"},
        messages=[{"role": "user", "content": "Patient diagnosis summary"}],
    )
    decision = engine.decide(
        request,
        DataFindings(contains_phi=True),
        RiskAssessment(tier=RiskTier.LOW, score=0.2),
    )

    assert decision.decision == Decision.DENY
    assert "global.global.deny_phi_external" in decision.violated_rules


def test_broadening_exception_requires_ticket_and_expiration() -> None:
    report = PolicyComposer().compose(
        [
            PolicyLayer("global", "global", GLOBAL_POLICY),
            PolicyLayer("local", "local_override", LOCAL_BROADENING, allow_broadening=True),
        ]
    )

    assert report.has_errors
    assert any(
        finding.code == "POLICY_COMPOSITION.EXCEPTION_METADATA_REQUIRED"
        for finding in report.findings
    )


def test_broadening_exception_with_metadata_is_warning_not_error() -> None:
    report = PolicyComposer().compose(
        [
            PolicyLayer("global", "global", GLOBAL_POLICY),
            PolicyLayer(
                "local",
                "local_override",
                LOCAL_BROADENING,
                allow_broadening=True,
                ticket="SEC-123",
                expires_at="2026-09-01",
            ),
        ]
    )

    assert not report.has_errors
    assert any(finding.code == "POLICY_COMPOSITION.BROADENING_EXCEPTION" for finding in report.findings)
    assert any("local_override.local.allow_phi_external" == rule["name"] for rule in report.composed_policy["rules"])


def test_load_policy_layers_from_manifest(tmp_path) -> None:
    global_path = tmp_path / "global.yaml"
    global_path.write_text(
        "id: global\n"
        "default: deny\n"
        "rules:\n"
        "  - name: deny_secrets\n"
        "    effect: deny\n"
        "    when:\n"
        "      data.contains_secrets: true\n",
        encoding="utf-8",
    )
    manifest = tmp_path / "stack.yaml"
    manifest.write_text(
        "layers:\n"
        "  - name: corporate\n"
        "    level: global\n"
        "    path: global.yaml\n",
        encoding="utf-8",
    )

    layers = load_policy_layers(manifest)

    assert len(layers) == 1
    assert layers[0].name == "corporate"
    assert layers[0].level == "global"
