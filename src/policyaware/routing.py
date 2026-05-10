from __future__ import annotations

from policyaware.models import GatewayRequest, ModelCandidate, PolicyDecision, RouteDecision


class ModelRouter:
    def __init__(self, models: list[ModelCandidate] | None = None):
        self.models = models or [
            ModelCandidate(name="local/sim-small", provider="local", cost_per_1k_tokens=0.0),
            ModelCandidate(
                name="openai-compatible/general",
                provider="openai-compatible",
                cost_per_1k_tokens=0.01,
                quality_score=0.9,
            ),
        ]

    def route(self, request: GatewayRequest, policy: PolicyDecision) -> RouteDecision:
        region = request.context.get("region")
        max_cost = request.context.get("max_cost_per_1k_tokens")
        capability = request.context.get("capability", "text")

        candidates = [
            model
            for model in self.models
            if model.available
            and capability in model.capabilities
            and (region is None or model.region == region)
            and (max_cost is None or model.cost_per_1k_tokens <= max_cost)
        ]

        if not candidates:
            fallback = next(model for model in self.models if model.available)
            return RouteDecision(
                model=fallback,
                fallback_used=True,
                reason="No model matched all constraints; using first available fallback.",
            )

        if policy.risk_tier.value in {"high", "critical"} or policy.risk_score >= 0.6:
            selected = sorted(candidates, key=lambda model: model.quality_score, reverse=True)[0]
            return RouteDecision(model=selected, reason="High-risk request routed to highest quality model.")

        selected = sorted(candidates, key=lambda model: (model.cost_per_1k_tokens, -model.quality_score))[0]
        return RouteDecision(model=selected, reason="Low/medium-risk request routed to lowest compliant cost.")
