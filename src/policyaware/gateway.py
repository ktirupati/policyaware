from __future__ import annotations

import time
from pathlib import Path

from policyaware.approvals import ApprovalClient, NoopApprovalClient
from policyaware.audit import AuditLogger
from policyaware.data_protection import DataProtectionEngine
from policyaware.evals import RuntimeEvaluator
from policyaware.models import Decision, GatewayRequest, GatewayResponse
from policyaware.policy import PolicyEngine
from policyaware.providers import ModelProvider, ProviderRegistry, SimulatedProvider, default_provider_registry
from policyaware.risk import RiskClassifier
from policyaware.routing import ModelRouter


class Gateway:
    def __init__(
        self,
        policy_engine: PolicyEngine,
        router: ModelRouter | None = None,
        provider: ModelProvider | None = None,
        provider_registry: ProviderRegistry | None = None,
        data_protection: DataProtectionEngine | None = None,
        risk_classifier: RiskClassifier | None = None,
        evaluator: RuntimeEvaluator | None = None,
        audit_logger: AuditLogger | None = None,
        approval_client: ApprovalClient | None = None,
    ):
        self.policy_engine = policy_engine
        self.router = router or ModelRouter()
        self.provider = provider or SimulatedProvider()
        self.provider_registry = provider_registry or default_provider_registry()
        self.provider_registry.register("local", self.provider)
        self.data_protection = data_protection or DataProtectionEngine()
        self.risk_classifier = risk_classifier or RiskClassifier()
        self.evaluator = evaluator or RuntimeEvaluator(self.data_protection)
        self.audit_logger = audit_logger or AuditLogger(Path(".policyaware/traces.jsonl"))
        self.approval_client = approval_client or NoopApprovalClient()

    @classmethod
    def from_policy_file(cls, path: str | Path) -> "Gateway":
        return cls(policy_engine=PolicyEngine.from_file(path))

    def chat(self, request: GatewayRequest) -> GatewayResponse:
        started_at = time.perf_counter()
        findings = self.data_protection.redact(request.prompt_text)
        risk = self.risk_classifier.classify(request, findings)
        decision = self.policy_engine.decide(request, findings, risk)

        if decision.decision == Decision.DENY:
            response = GatewayResponse(content="", policy=decision, risk=risk)
            self.audit_logger.record(request, response, started_at)
            return response

        if decision.decision == Decision.REQUIRE_APPROVAL:
            approval = self.approval_client.submit(request, decision)
            response = GatewayResponse(
                content=f"Request requires approval before model execution: {approval.approval_id}",
                policy=decision,
                risk=risk,
                metadata={"approval": approval.model_dump(mode="json")},
            )
            self.audit_logger.record(request, response, started_at)
            return response

        executable_request = request
        if "redact" in decision.actions and findings.redacted_text is not None:
            executable_request = request.model_copy(
                update={"messages": [{"role": "user", "content": findings.redacted_text}]}
            )

        route = self.router.route(executable_request, decision)
        output = self.provider_registry.for_model(route.model).generate(executable_request, route.model)
        evals = self.evaluator.evaluate(executable_request, output, decision)
        response = GatewayResponse(content=output, policy=decision, route=route, evals=evals, risk=risk)
        trace = self.audit_logger.record(executable_request, response, started_at)
        response.metadata["audit"] = trace.model_dump(mode="json")
        return response
