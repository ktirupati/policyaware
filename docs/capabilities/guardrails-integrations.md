# Guardrails Integrations

PolicyAware can orchestrate optional guardrail libraries as part of a full-stack AI governance flow.

PolicyAware remains the control plane:

- policy enforcement
- risk classification
- model routing
- audit traces
- evaluation
- compliance evidence
- local code scanning

Optional guardrail libraries become adapters:

- NeMo Guardrails for conversational rails and dialog safety.
- Guardrails AI for input/output validation, structured output checks, and validators.

## Install

Base install:

```bash
pip install policyaware
```

NeMo Guardrails:

```bash
pip install "policyaware[nemo]"
```

Guardrails AI:

```bash
pip install "policyaware[guardrails-ai]"
```

Full optional stack:

```bash
pip install "policyaware[full]"
```

These integrations are optional so normal users can keep the lightweight install:

```bash
pip install policyaware
```

## Core API

| API | Purpose |
| --- | --- |
| `GuardrailResult` | Normalized allow/block/transform result. |
| `GuardrailAdapter` | Protocol for input and output guard adapters. |
| `NeMoGuardrailsAdapter` | Optional adapter for NVIDIA NeMo Guardrails. |
| `GuardrailsAIAdapter` | Optional adapter for Guardrails AI. |
| `Gateway.add_input_guard(...)` | Run guard before model routing/execution. |
| `Gateway.add_output_guard(...)` | Run guard after model output before final response. |
| `Gateway.add_guard(...)` | Run the same adapter for input and output phases. |

## YAML-Driven Guard Configuration

For enterprise teams, the recommended pattern is to define guard usage in policy YAML so guard execution is reviewable as policy-as-code.

```yaml
id: full_stack_guardrails_policy
schema_version: "0.2"
default: deny

guards:
  input:
    - name: nemo
      config_path: rails/
      when:
        request.task_type: chatbot

  output:
    - name: guardrails_ai
      rail_spec: guardrails/spec.rail
      when:
        request.output_format: json

rules:
  - name: allow_support
    effect: allow
    when:
      user.role_in: [support_agent, developer]
      request.risk_in: [low, medium]
```

PolicyAware automatically loads known guard names:

| Guard Name | Adapter |
| --- | --- |
| `nemo` | `NeMoGuardrailsAdapter` |
| `nemoguardrails` | `NeMoGuardrailsAdapter` |
| `guardrails_ai` | `GuardrailsAIAdapter` |
| `guardrails-ai` | `GuardrailsAIAdapter` |

For custom internal validators, pass a `guard_registry`:

```python
from policyaware import Gateway, PolicyEngine

gateway = Gateway(
    policy_engine=PolicyEngine.from_file("policyaware.yaml"),
    guard_registry={"internal_safety": InternalSafetyGuard()},
)
```

Inspect guards declared in a policy:

```bash
policyaware guards list policyaware.yaml
```

## NeMo Guardrails Example

```python
from policyaware import Gateway, GatewayRequest, NeMoGuardrailsAdapter

gateway = Gateway.from_policy_file("policyaware.yaml")
gateway.add_input_guard(
    NeMoGuardrailsAdapter(config_path="rails/")
)

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="chatbot",
        user={"id": "u_123", "role": "support_agent"},
        context={"region": "us", "risk": "low", "task_type": "chatbot"},
        messages=[{"role": "user", "content": "Help me with this account question."}],
    )
)

print(response.policy.decision)
print(response.metadata["guardrails"])
```

## Guardrails AI Example

```python
from policyaware import Gateway, GatewayRequest, GuardrailsAIAdapter

gateway = Gateway.from_policy_file("policyaware.yaml")
gateway.add_output_guard(
    GuardrailsAIAdapter(rail_spec="guardrails/spec.rail")
)

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="structured-output-agent",
        user={"id": "u_456", "role": "analyst"},
        context={"region": "us", "risk": "medium", "task_type": "structured_output"},
        messages=[{"role": "user", "content": "Return a validated JSON summary."}],
    )
)

print(response.content)
print(response.metadata["guardrails"])
```

## Combined Full-Stack Flow

```python
from policyaware import Gateway, GuardrailsAIAdapter, NeMoGuardrailsAdapter

gateway = Gateway.from_policy_file("policyaware.yaml")

gateway.add_input_guard(NeMoGuardrailsAdapter(config_path="rails/"))
gateway.add_output_guard(GuardrailsAIAdapter(rail_spec="guardrails/spec.rail"))
```

Execution order:

```text
GatewayRequest
  -> data protection
  -> ML signals
  -> risk classification
  -> YAML policy decision
  -> input guard adapters
  -> model routing
  -> model provider
  -> output guard adapters
  -> runtime evaluation
  -> audit trace
  -> GatewayResponse
```

## Guardrail Results In Metadata

Guard results are available in response metadata:

```python
print(response.metadata["guardrails"])
```

Shape:

```json
{
  "input": [
    {
      "name": "nemo",
      "allowed": true,
      "transformed_text": null,
      "reason": "Allowed by NeMo Guardrails.",
      "score": 1.0,
      "metadata": {}
    }
  ],
  "output": [
    {
      "name": "guardrails_ai",
      "allowed": true,
      "transformed_text": null,
      "reason": "Allowed by Guardrails AI.",
      "score": 1.0,
      "metadata": {}
    }
  ]
}
```

## Custom Adapter

You can integrate any internal validator with the same adapter contract.

```python
from policyaware import GatewayRequest, GuardrailResult


class InternalSafetyGuard:
    name = "internal_safety"

    def inspect_input(self, request: GatewayRequest) -> GuardrailResult:
        if "forbidden action" in request.prompt_text.lower():
            return GuardrailResult(
                name=self.name,
                allowed=False,
                reason="Blocked by internal safety guard.",
                score=0.0,
            )
        return GuardrailResult(name=self.name)

    def inspect_output(self, request: GatewayRequest, output_text: str) -> GuardrailResult:
        return GuardrailResult(name=self.name)
```

## Design Guidance

Use PolicyAware for enterprise-wide governance:

- deny-by-default policy
- tenant, role, region, risk, and cost rules
- model routing
- audit and compliance evidence
- evaluation and regression testing

Use NeMo Guardrails for conversation-specific behavior:

- dialog rails
- topic control
- conversational flows

Use Guardrails AI for validator-specific behavior:

- structured output validation
- schema checks
- custom validators

This keeps PolicyAware vendor-neutral and lightweight while still supporting full-stack governance.
