from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from policyaware.audit import estimate_tokens
from policyaware.gateway import Gateway
from policyaware.models import DataFindings, EvalResult, GatewayRequest, PolicyDecision, RiskAssessment


@dataclass
class PolicyAwareCallbackResult:
    """Governance result captured by framework callback integrations."""

    prompt_text: str
    output_text: str
    policy_decision: PolicyDecision
    risk: RiskAssessment
    input_findings: DataFindings
    output_findings: DataFindings
    evals: list[EvalResult] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.policy_decision.decision.value in {"allow", "conditional_allow"}

    @property
    def contains_output_sensitive_data(self) -> bool:
        return self.output_findings.contains_sensitive

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "decision": self.policy_decision.decision.value,
            "risk_tier": self.risk.tier.value,
            "risk_score": self.risk.score,
            "reason_codes": self.policy_decision.reason_codes,
            "matched_rules": self.policy_decision.matched_rules,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "input_findings": self.input_findings.model_dump(mode="json"),
            "output_findings": self.output_findings.model_dump(mode="json"),
            "evals": [result.model_dump(mode="json") for result in self.evals],
            "metadata": self.metadata,
        }


class BasePolicyAwareCallbackHandler:
    """Framework-neutral callback core for streaming LLM integrations.

    The callback checks prompts before/around generation and reviews the aggregated
    output when the framework reports completion. It does not call a provider or
    block token streaming.
    """

    def __init__(
        self,
        config: str | Path | None = None,
        gateway: Gateway | None = None,
        *,
        tenant: str = "default",
        app: str = "integration",
        user: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        if gateway is None and config is None:
            raise ValueError("PolicyAware callback requires either config='policy.yaml' or gateway=Gateway(...).")
        self.gateway = gateway or Gateway.from_policy_file(config)  # type: ignore[arg-type]
        self.tenant = tenant
        self.app = app
        self.user = user or {"role": "developer"}
        self.context = context or {"region": "us", "task_type": "chain", "risk": "low"}
        self.metadata = metadata or {}
        self.prompt_text = ""
        self.output_text = ""
        self.last_result: PolicyAwareCallbackResult | None = None
        self.last_error: str | None = None
        self._chunks: list[str] = []

    def start(self, prompts: Any = None, **metadata: Any) -> None:
        self.prompt_text = _text_from_any(prompts)
        self.output_text = ""
        self.last_result = None
        self.last_error = None
        self._chunks = []
        self.metadata = {**self.metadata, **metadata}

    def add_token(self, token: Any) -> None:
        if token is not None:
            self._chunks.append(str(token))

    def finish(self, output: Any = None, **metadata: Any) -> PolicyAwareCallbackResult:
        if metadata:
            self.metadata = {**self.metadata, **metadata}
        self.output_text = _text_from_any(output) if output is not None else "".join(self._chunks)
        request = GatewayRequest(
            tenant=self.tenant,
            app=self.app,
            user=self.user,
            context=self.context,
            messages=[{"role": "user", "content": self.prompt_text}],
            metadata=self.metadata,
        )
        input_findings = self.gateway.data_protection.redact(self.prompt_text)
        risk = self.gateway.risk_classifier.classify(request, input_findings)
        decision = self.gateway.policy_engine.decide(request, input_findings, risk)
        output_findings = self.gateway.data_protection.inspect(self.output_text)
        evals = self.gateway.evaluator.evaluate(request, self.output_text, decision)
        self.last_result = PolicyAwareCallbackResult(
            prompt_text=self.prompt_text,
            output_text=self.output_text,
            policy_decision=decision,
            risk=risk,
            input_findings=input_findings,
            output_findings=output_findings,
            evals=evals,
            input_tokens=estimate_tokens(self.prompt_text),
            output_tokens=estimate_tokens(self.output_text),
            metadata=dict(self.metadata),
        )
        return self.last_result

    def error(self, error: BaseException | str) -> None:
        self.last_error = str(error)


def _text_from_any(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("content", "text", "prompt", "query", "query_str", "response", "output"):
            if key in value:
                return _text_from_any(value[key])
        if "messages" in value:
            return _text_from_any(value["messages"])
        return " ".join(_text_from_any(item) for item in value.values() if item is not None).strip()
    if isinstance(value, (list, tuple)):
        return "\n".join(part for item in value if (part := _text_from_any(item))).strip()
    message = getattr(value, "message", None)
    if message is not None:
        return _text_from_any(message)
    for attr in ("content", "text", "response", "output"):
        attr_value = getattr(value, attr, None)
        if attr_value is not None:
            return _text_from_any(attr_value)
    generations = getattr(value, "generations", None)
    if generations is not None:
        return _text_from_any(generations)
    return str(value)
