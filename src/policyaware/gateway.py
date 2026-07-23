from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from policyaware.approvals import ApprovalClient, NoopApprovalClient
from policyaware.audit import AuditLogger
from policyaware.data_protection import DataProtectionEngine
from policyaware.evals import RuntimeEvaluator
from policyaware.guardrails import GuardrailAdapter, GuardrailResult, GuardrailsAIAdapter, NeMoGuardrailsAdapter
from policyaware.ml import MLClassifier, NoopMLClassifier
from policyaware.models import Decision, GatewayRequest, GatewayResponse, PolicyDecision
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
        ml_classifier: MLClassifier | None = None,
        input_guards: list[GuardrailAdapter] | None = None,
        output_guards: list[GuardrailAdapter] | None = None,
        guard_registry: dict[str, GuardrailAdapter] | None = None,
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
        self.ml_classifier = ml_classifier or NoopMLClassifier()
        self.input_guards = list(input_guards or [])
        self.output_guards = list(output_guards or [])
        self.guard_registry = dict(guard_registry or {})
        self._configure_policy_guards()

    @classmethod
    def from_policy_file(cls, path: str | Path) -> "Gateway":
        return cls(policy_engine=PolicyEngine.from_file(path))

    def add_input_guard(self, guard: GuardrailAdapter) -> "Gateway":
        self.guard_registry.setdefault(guard.name, guard)
        self.input_guards.append(guard)
        return self

    def add_output_guard(self, guard: GuardrailAdapter) -> "Gateway":
        self.guard_registry.setdefault(guard.name, guard)
        self.output_guards.append(guard)
        return self

    def add_guard(self, guard: GuardrailAdapter) -> "Gateway":
        self.add_input_guard(guard)
        self.add_output_guard(guard)
        return self

    def chat(self, request: GatewayRequest) -> GatewayResponse:
        started_at = time.perf_counter()
        findings = self.data_protection.redact(request.prompt_text)
        ml_assessment = self.ml_classifier.classify(request.prompt_text, request)
        policy_request = request.model_copy(
            update={
                "metadata": {
                    **request.metadata,
                    "ml": ml_assessment.as_policy_context(),
                }
            }
        )
        risk = self.risk_classifier.classify(policy_request, findings)
        decision = self.policy_engine.decide(policy_request, findings, risk)

        if decision.decision == Decision.DENY:
            response = GatewayResponse(content="", policy=decision, risk=risk)
            response.metadata["ml"] = ml_assessment.model_dump(mode="json")
            self.audit_logger.record(policy_request, response, started_at)
            return response

        if decision.decision == Decision.REQUIRE_APPROVAL:
            approval = self.approval_client.submit(policy_request, decision)
            response = GatewayResponse(
                content=f"Request requires approval before model execution: {approval.approval_id}",
                policy=decision,
                risk=risk,
                metadata={
                    "approval": approval.model_dump(mode="json"),
                    "ml": ml_assessment.model_dump(mode="json"),
                },
            )
            self.audit_logger.record(policy_request, response, started_at)
            return response

        executable_request = policy_request
        if "redact" in decision.actions and findings.redacted_text is not None:
            executable_request = request.model_copy(
                update={"messages": [{"role": "user", "content": findings.redacted_text}]}
            )

        input_guard_results = self._run_input_guards(executable_request)
        blocked_input = next((result for result in input_guard_results if not result.allowed), None)
        if blocked_input:
            guard_decision = self._guard_denied_decision(
                decision,
                reason=blocked_input.reason,
                code="GUARD.INPUT_BLOCKED",
                guard_name=blocked_input.name,
            )
            response = GatewayResponse(
                content="",
                policy=guard_decision,
                risk=risk,
                metadata={
                    "ml": ml_assessment.model_dump(mode="json"),
                    "guardrails": [result.__dict__ for result in input_guard_results],
                },
            )
            self.audit_logger.record(executable_request, response, started_at)
            return response
        executable_request = self._request_with_guard_transforms(executable_request, input_guard_results)

        route = self.router.route(executable_request, decision)
        output = self.provider_registry.for_model(route.model).generate(executable_request, route.model)
        output_guard_results = self._run_output_guards(executable_request, output)
        blocked_output = next((result for result in output_guard_results if not result.allowed), None)
        if blocked_output:
            guard_decision = self._guard_denied_decision(
                decision,
                reason=blocked_output.reason,
                code="GUARD.OUTPUT_BLOCKED",
                guard_name=blocked_output.name,
            )
            response = GatewayResponse(
                content="",
                policy=guard_decision,
                route=route,
                risk=risk,
                metadata={
                    "ml": ml_assessment.model_dump(mode="json"),
                    "guardrails": {
                        "input": [result.__dict__ for result in input_guard_results],
                        "output": [result.__dict__ for result in output_guard_results],
                    },
                },
            )
            trace = self.audit_logger.record(executable_request, response, started_at)
            response.metadata["audit"] = trace.model_dump(mode="json")
            return response
        output = self._output_with_guard_transforms(output, output_guard_results)
        evals = self.evaluator.evaluate(executable_request, output, decision)
        response = GatewayResponse(content=output, policy=decision, route=route, evals=evals, risk=risk)
        response.metadata["ml"] = ml_assessment.model_dump(mode="json")
        response.metadata["guardrails"] = {
            "input": [result.__dict__ for result in input_guard_results],
            "output": [result.__dict__ for result in output_guard_results],
        }
        trace = self.audit_logger.record(executable_request, response, started_at)
        response.metadata["audit"] = trace.model_dump(mode="json")
        return response

    def _run_input_guards(self, request: GatewayRequest) -> list[GuardrailResult]:
        return [
            guard.inspect_input(request)
            for guard in self.input_guards
            if self._guard_matches_request(guard, request, "input")
        ]

    def _run_output_guards(self, request: GatewayRequest, output: str) -> list[GuardrailResult]:
        return [
            guard.inspect_output(request, output)
            for guard in self.output_guards
            if self._guard_matches_request(guard, request, "output")
        ]

    def _configure_policy_guards(self) -> None:
        guards = self.policy_engine.policy.get("guards", {})
        if not isinstance(guards, dict):
            return
        for phase, target in (("input", self.input_guards), ("output", self.output_guards)):
            for spec in guards.get(phase, []) or []:
                if not isinstance(spec, dict):
                    continue
                guard = self._guard_from_spec(spec)
                guard._policyaware_when = spec.get("when", {})  # type: ignore[attr-defined]
                guard._policyaware_phase = phase  # type: ignore[attr-defined]
                target.append(guard)

    def _guard_from_spec(self, spec: dict[str, Any]) -> GuardrailAdapter:
        name = str(spec.get("name", "")).strip()
        if name in self.guard_registry:
            return self.guard_registry[name]
        if name in {"nemo", "nemoguardrails"}:
            guard = NeMoGuardrailsAdapter(config_path=spec.get("config_path") or spec.get("config"))
        elif name in {"guardrails_ai", "guardrails-ai", "guardrails"}:
            guard = GuardrailsAIAdapter(
                rail_spec=spec.get("rail_spec") or spec.get("rail") or spec.get("spec"),
                validate_input=bool(spec.get("validate_input", True)),
                validate_output=bool(spec.get("validate_output", True)),
            )
        else:
            raise ValueError(
                f"Unknown guard '{name}'. Register a custom guard with guard_registry or add_guard()."
            )
        self.guard_registry[name] = guard
        return guard

    def _guard_matches_request(self, guard: GuardrailAdapter, request: GatewayRequest, phase: str) -> bool:
        when = getattr(guard, "_policyaware_when", None)
        guard_phase = getattr(guard, "_policyaware_phase", phase)
        if guard_phase != phase:
            return True
        if not when:
            return True
        context = {
            "tenant": request.tenant,
            "app": request.app,
            "user": request.user,
            "request": {
                **request.context,
                "tenant": request.tenant,
                "app": request.app,
                "tools_requested": bool(request.tools),
            },
            "metadata": request.metadata,
        }
        return _matches_guard_when(when, context)

    def _request_with_guard_transforms(
        self, request: GatewayRequest, results: list[GuardrailResult]
    ) -> GatewayRequest:
        text = request.prompt_text
        for result in results:
            if result.transformed_text is not None:
                text = result.transformed_text
        if text == request.prompt_text:
            return request
        return request.model_copy(update={"messages": [{"role": "user", "content": text}]})

    def _output_with_guard_transforms(self, output: str, results: list[GuardrailResult]) -> str:
        for result in results:
            if result.transformed_text is not None:
                output = result.transformed_text
        return output

    def _guard_denied_decision(
        self,
        original: PolicyDecision,
        *,
        reason: str,
        code: str,
        guard_name: str,
    ) -> PolicyDecision:
        return PolicyDecision(
            decision=Decision.DENY,
            actions=[*original.actions, "guardrail_block"],
            matched_rules=original.matched_rules,
            violated_rules=[*original.violated_rules, guard_name],
            reason=reason,
            risk_score=original.risk_score,
            risk_tier=original.risk_tier,
            reason_codes=[*original.reason_codes, code],
            remediation=[
                *original.remediation,
                "Review the guardrail result, adjust the request/output, or route to human review.",
            ],
        )


def _matches_guard_when(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    for dotted_key, expected_value in expected.items():
        operator = "eq"
        key = dotted_key
        for suffix, op in {
            "_not_in": "not_in",
            "_in": "in",
            "_lte": "lte",
            "_gte": "gte",
        }.items():
            if dotted_key.endswith(suffix):
                key = dotted_key[: -len(suffix)]
                operator = op
                break
        actual_value = _lookup_guard_value(actual, key)
        if not _compare_guard_value(actual_value, expected_value, operator):
            return False
    return True


def _lookup_guard_value(source: dict[str, Any], dotted_key: str) -> Any:
    current: Any = source
    for part in dotted_key.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _compare_guard_value(actual: Any, expected: Any, operator: str) -> bool:
    if operator == "in":
        return actual in expected
    if operator == "not_in":
        return actual not in expected
    if operator == "lte":
        return actual is not None and actual <= expected
    if operator == "gte":
        return actual is not None and actual >= expected
    return actual == expected
