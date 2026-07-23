from policyaware import Gateway, GatewayRequest, GuardrailResult, PolicyEngine


class DemoGuard:
    name = "demo_guard"

    def inspect_input(self, request: GatewayRequest) -> GuardrailResult:
        return GuardrailResult(
            name=self.name,
            allowed=True,
            transformed_text=request.prompt_text.replace("unsafe wording", "safe wording"),
            reason="Demo input guard allowed the request.",
        )

    def inspect_output(self, request: GatewayRequest, output_text: str) -> GuardrailResult:
        return GuardrailResult(
            name=self.name,
            allowed=True,
            transformed_text="validated output",
            reason="Demo output guard validated the response.",
        )


gateway = Gateway(
    policy_engine=PolicyEngine.from_file("policy.yaml"),
    guard_registry={"demo_guard": DemoGuard()},
)

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="full-stack-guardrails-demo",
        user={"id": "u_123", "role": "support_agent"},
        context={"region": "us", "risk": "low", "task_type": "support"},
        messages=[{"role": "user", "content": "Summarize this ticket with unsafe wording."}],
    )
)

print(f"decision={response.policy.decision.value}")
print(f"content={response.content}")
print(f"input_guard={response.metadata['guardrails']['input'][0]['name']}")
print(f"output_guard={response.metadata['guardrails']['output'][0]['name']}")
