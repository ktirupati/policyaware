from policyaware import (
    AuditLogger,
    DataProtectionEngine,
    Gateway,
    GatewayRequest,
    ModelRouter,
    PolicyEngine,
    PolicySchemaValidator,
    RiskClassifier,
    SQLiteAuditLogger,
    TraceViewer,
)


def test_core_public_api_exports_are_available() -> None:
    assert Gateway is not None
    assert GatewayRequest is not None
    assert PolicyEngine is not None
    assert PolicySchemaValidator is not None
    assert DataProtectionEngine is not None
    assert RiskClassifier is not None
    assert ModelRouter is not None
    assert AuditLogger is not None
    assert SQLiteAuditLogger is not None
    assert TraceViewer is not None
