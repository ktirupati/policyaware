# Full-Stack Guardrails

This example shows how PolicyAware can orchestrate optional guardrail libraries while remaining the enterprise governance control plane.

PolicyAware does not replace NeMo Guardrails or Guardrails AI. It coordinates them:

- PolicyAware: policy, risk, routing, audit, evaluation, scan, compliance evidence.
- NeMo Guardrails: conversational rails and dialog safety.
- Guardrails AI: structured validation and input/output validators.

## Install

Base install:

```bash
pip install policyaware
```

Optional integrations:

```bash
pip install "policyaware[nemo]"
pip install "policyaware[guardrails-ai]"
pip install "policyaware[full]"
```

## Run

The demo uses a local fake guard so it runs without external dependencies:

```bash
python demo.py
```

Expected output:

```text
decision=allow
content=validated output
input_guard=demo_guard
output_guard=demo_guard
```

## YAML-Driven Guards

PolicyAware policies can declare which guards run for each phase.

```yaml
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
```

For custom guards, register the object by name:

```python
from policyaware import Gateway, PolicyEngine

gateway = Gateway(
    policy_engine=PolicyEngine.from_file("policy.yaml"),
    guard_registry={"demo_guard": DemoGuard()},
)
```

## Real NeMo Guardrails Adapter

```python
from policyaware import Gateway, NeMoGuardrailsAdapter

gateway = Gateway.from_policy_file("policy.yaml")
gateway.add_input_guard(
    NeMoGuardrailsAdapter(config_path="rails/")
)
```

## Real Guardrails AI Adapter

```python
from policyaware import Gateway, GuardrailsAIAdapter

gateway = Gateway.from_policy_file("policy.yaml")
gateway.add_output_guard(
    GuardrailsAIAdapter(rail_spec="guardrails/spec.rail")
)
```

## Combined

```python
from policyaware import Gateway, GuardrailsAIAdapter, NeMoGuardrailsAdapter

gateway = Gateway.from_policy_file("policy.yaml")
gateway.add_input_guard(NeMoGuardrailsAdapter(config_path="rails/"))
gateway.add_output_guard(GuardrailsAIAdapter(rail_spec="guardrails/spec.rail"))
```

All guard results are recorded in `response.metadata["guardrails"]` and included in audit traces.
