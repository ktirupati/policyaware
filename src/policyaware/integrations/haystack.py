from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from policyaware.gateway import Gateway
from policyaware.integrations.callbacks import PolicyAwareCallbackResult
from policyaware.models import Decision, GatewayRequest, ToolCallRequest, ToolDecision
from policyaware.tools import ToolPolicyEngine


@dataclass
class PolicyAwareHaystackResult:
    """Result emitted by PolicyAware Haystack-style components."""

    allowed: bool
    text: str
    decision: str
    reason: str
    reason_codes: list[str]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "text": self.text,
            "decision": self.decision,
            "reason": self.reason,
            "reason_codes": self.reason_codes,
            "metadata": self.metadata,
        }


class PolicyAwareInputComponent:
    """Haystack-style input governance component.

    This class intentionally has no hard dependency on Haystack. It exposes a
    `run(...)` method that can be used in Haystack pipelines or called directly
    in examples/tests.
    """

    def __init__(
        self,
        config: str | Path | None = None,
        gateway: Gateway | None = None,
        *,
        tenant: str = "default",
        app: str = "haystack",
        user: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ):
        if gateway is None and config is None:
            raise ValueError("PolicyAware Haystack component requires config or gateway.")
        self.gateway = gateway or Gateway.from_policy_file(config)  # type: ignore[arg-type]
        self.tenant = tenant
        self.app = app
        self.user = user or {"role": "developer"}
        self.context = context or {"region": "us", "risk": "low", "task_type": "rag_query"}

    def run(
        self,
        query: str | None = None,
        prompt: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        text = prompt if prompt is not None else query or ""
        request = GatewayRequest(
            tenant=kwargs.get("tenant", self.tenant),
            app=kwargs.get("app", self.app),
            user=kwargs.get("user", self.user),
            context=kwargs.get("context", self.context),
            messages=[{"role": "user", "content": text}],
            metadata=kwargs.get("metadata", {}),
        )
        findings = self.gateway.data_protection.redact(text)
        risk = self.gateway.risk_classifier.classify(request, findings)
        decision = self.gateway.policy_engine.decide(request, findings, risk)
        output_text = findings.redacted_text if "redact" in decision.actions else text
        allowed = decision.decision in {Decision.ALLOW, Decision.CONDITIONAL_ALLOW}
        result = PolicyAwareHaystackResult(
            allowed=allowed,
            text=output_text if allowed else "",
            decision=decision.decision.value,
            reason=decision.reason,
            reason_codes=decision.reason_codes,
            metadata={
                "risk": risk.model_dump(mode="json"),
                "policy": decision.model_dump(mode="json"),
                "input_findings": findings.model_dump(mode="json"),
            },
        )
        return {
            "query": result.text,
            "prompt": result.text,
            "allowed": result.allowed,
            "decision": result.decision,
            "policyaware": result.to_dict(),
        }


class PolicyAwareOutputComponent:
    """Haystack-style output governance and evaluation component."""

    def __init__(
        self,
        config: str | Path | None = None,
        gateway: Gateway | None = None,
        *,
        tenant: str = "default",
        app: str = "haystack",
        user: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ):
        if gateway is None and config is None:
            raise ValueError("PolicyAware Haystack component requires config or gateway.")
        self.gateway = gateway or Gateway.from_policy_file(config)  # type: ignore[arg-type]
        self.tenant = tenant
        self.app = app
        self.user = user or {"role": "developer"}
        self.context = context or {
            "region": "us",
            "risk": "low",
            "task_type": "rag_answer",
            "require_citations": True,
        }

    def run(
        self,
        answer: str | None = None,
        query: str | None = None,
        prompt: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        output_text = answer or kwargs.get("response") or ""
        prompt_text = prompt or query or ""
        request = GatewayRequest(
            tenant=kwargs.get("tenant", self.tenant),
            app=kwargs.get("app", self.app),
            user=kwargs.get("user", self.user),
            context=kwargs.get("context", self.context),
            messages=[{"role": "user", "content": prompt_text}],
            metadata=kwargs.get("metadata", {}),
        )
        input_findings = self.gateway.data_protection.redact(prompt_text)
        risk = self.gateway.risk_classifier.classify(request, input_findings)
        decision = self.gateway.policy_engine.decide(request, input_findings, risk)
        output_findings = self.gateway.data_protection.inspect(output_text)
        evals = self.gateway.evaluator.evaluate(request, output_text, decision)
        callback_result = PolicyAwareCallbackResult(
            prompt_text=prompt_text,
            output_text=output_text,
            policy_decision=decision,
            risk=risk,
            input_findings=input_findings,
            output_findings=output_findings,
            evals=evals,
        )
        return {
            "answer": output_text,
            "allowed": callback_result.allowed and not output_findings.contains_sensitive,
            "decision": decision.decision.value,
            "policyaware": callback_result.to_dict(),
        }


class PolicyAwareToolGovernanceComponent:
    """Haystack-style component for governing agent/tool actions."""

    def __init__(
        self,
        tool_policy: str | Path | ToolPolicyEngine,
        *,
        agent_id: str = "haystack_agent",
        tenant: str = "default",
        user: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ):
        self.tool_policy = (
            tool_policy if isinstance(tool_policy, ToolPolicyEngine) else ToolPolicyEngine.from_file(tool_policy)
        )
        self.agent_id = agent_id
        self.tenant = tenant
        self.user = user or {"role": "developer"}
        self.context = context or {"region": "us", "risk": "low", "task_type": "tool_call"}

    def run(
        self,
        connector_id: str,
        action: str,
        arguments: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        request = ToolCallRequest(
            agent_id=kwargs.get("agent_id", self.agent_id),
            connector_id=connector_id,
            action=action,
            arguments=arguments or {},
            tenant=kwargs.get("tenant", self.tenant),
            user=kwargs.get("user", self.user),
            context=kwargs.get("context", self.context),
        )
        decision: ToolDecision = self.tool_policy.decide(request)
        return {
            "allowed": decision.decision == Decision.ALLOW,
            "approval_required": decision.approval_required,
            "decision": decision.decision.value,
            "reason": decision.reason,
            "reason_codes": decision.reason_codes,
            "policyaware": decision.model_dump(mode="json"),
        }
