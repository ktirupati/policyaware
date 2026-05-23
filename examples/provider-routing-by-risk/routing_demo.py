from __future__ import annotations

from pathlib import Path

from policyaware import Gateway, GatewayRequest, ModelCandidate, ModelRouter


gateway = Gateway.from_policy_file(Path(__file__).with_name("policy.yaml"))
gateway.router = ModelRouter(
    [
        ModelCandidate(
            name="external/low-cost",
            provider="local",
            region="us",
            cost_per_1k_tokens=0.001,
            quality_score=0.70,
        ),
        ModelCandidate(
            name="internal/approved",
            provider="local",
            region="us",
            cost_per_1k_tokens=0.02,
            quality_score=0.95,
        ),
    ]
)


cases = {
    "public_safe": ("developer", "Summarize the public release notes."),
    "sensitive_healthcare": ("clinician", "Patient id ABCDE diagnosis: diabetes."),
    "secret_request": ("developer", "Use api_key_abcdefghijklmnop123456 to call the API."),
}

for name, (role, prompt) in cases.items():
    context = {"region": "us", "task_type": "routing_demo"}
    if name == "sensitive_healthcare":
        context.update({"domain": "healthcare", "autonomy": "agentic"})
    response = gateway.chat(
        GatewayRequest(
            tenant="acme",
            app="provider-routing-by-risk",
            user={"id": "user_1", "role": role},
            context=context,
            messages=[{"role": "user", "content": prompt}],
        )
    )
    route = response.route.model.name if response.route else "none"
    print(
        f"{name} route={route} "
        f"decision={response.policy.decision.value} risk={response.risk.tier.value}"
    )
