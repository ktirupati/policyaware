from policyaware.data_protection import DataProtectionEngine
from policyaware.models import GatewayRequest, RiskTier
from policyaware.risk import RiskClassifier


def test_healthcare_phi_tool_request_is_high_or_critical() -> None:
    request = GatewayRequest(
        tenant="acme",
        app="test",
        user={"role": "analyst"},
        context={"domain": "healthcare", "autonomy": "agentic", "business_impact": "high"},
        tools=[{"connector": "ehr", "action": "read_record"}],
        messages=[{"role": "user", "content": "Review patient id ABCDE diagnosis: flu"}],
    )
    findings = DataProtectionEngine().inspect(request.prompt_text)

    risk = RiskClassifier().classify(request, findings)

    assert risk.tier in {RiskTier.HIGH, RiskTier.CRITICAL}
    assert "RISK.TOOL_USE" in risk.reason_codes

