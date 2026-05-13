# Gateway Orchestration

## What It Does

`Gateway` is the main entry point. It runs a request through:

1. data protection
2. optional ML signal classification
3. risk classification
4. policy decision
5. approval check
6. model routing
7. provider execution
8. runtime evaluation
9. audit logging

## Imports

```python
from policyaware import Gateway, GatewayRequest
```

## Main APIs

| API | Type | What It Does |
| --- | --- | --- |
| `Gateway.from_policy_file(path)` | class method | Creates a gateway from a YAML policy file. |
| `gateway.chat(request)` | method | Runs a full governed request through policy, routing, provider execution, evals, and audit. |
| `gateway.process(...)` | method | Convenience request-processing helper when supported by the app integration. |
| `GatewayRequest(...)` | model | Standard request object passed into the gateway. |
| `GatewayResponse(...)` | model | Standard response object returned by the gateway. |

## `GatewayRequest` Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `tenant` | `str` | Tenant or organization boundary. |
| `app` | `str` | Calling application name. |
| `user` | `dict` | User identity and attributes, such as `id` and `role`. |
| `context` | `dict` | Region, task type, risk hints, domain, autonomy, and workflow metadata. |
| `messages` | `list[dict]` | Chat-style input messages. |
| `tools` | `list[dict]` | Tool definitions or tool-call metadata. |
| `metadata` | `dict` | Extra application metadata. |
| `request_id` | `str` | Generated request ID unless supplied. |
| `prompt_text` | property | Combined message text used by data protection and risk checks. |

## `GatewayResponse` Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `content` | `str` | Final model/provider response text, or blocked/approval message. |
| `policy` | `PolicyDecision` | Policy decision and reason codes. |
| `route` | `RouteDecision \| None` | Selected model/provider route when a model was called. |
| `evals` | `list[EvalResult]` | Runtime evaluation results. |
| `trace_id` | `str` | Audit trace identifier. |
| `metadata` | `dict` | Extra execution metadata such as approval or ML signals. |
| `risk` | `RiskAssessment \| None` | Risk tier and factors calculated for the request. |

## Basic Request

```python
from policyaware import Gateway, GatewayRequest

gateway = Gateway.from_policy_file("examples/policies/basic.yaml")

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="support-copilot",
        user={"id": "u1", "role": "support_agent"},
        context={"region": "us", "risk": "low", "task_type": "support"},
        messages=[{"role": "user", "content": "Email jane@example.com"}],
    )
)

print(response.content)
print(response.policy.decision.value)
print(response.policy.reason_codes)
print(response.trace_id)
```

## Expected Response Fields

```python
response.content
response.policy
response.route
response.evals
response.risk
response.trace_id
response.metadata
```

## Approval Path

If policy returns `require_approval`, the gateway does not call the model.

```python
print(response.policy.decision.value)
print(response.metadata.get("approval"))
```

## Local Provider By Default

If no provider is configured, PolicyAware uses `SimulatedProvider`, which makes local testing safe and offline.
