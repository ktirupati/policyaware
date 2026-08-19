# LLM Token Budget And Cost Controls

PolicyAware helps teams apply Python LLM token budget controls, rate limits, model routing constraints, and agent-loop safeguards before a request reaches a model provider.

This page is for searches like Python LLM token budget rate limiting, stop autonomous agent runaway loop, and cost-aware LLM gateway.

## Install

```bash
pip install policyaware
```

## Copy-Paste YAML

```yaml
name: token-budget-cost-controls
version: 1
default_decision: deny

budgets:
  default:
    max_input_tokens: 4000
    max_output_tokens: 1000
    max_estimated_cost_usd: 0.25
    max_tool_calls: 5
  high_risk:
    max_input_tokens: 2000
    max_output_tokens: 500
    max_estimated_cost_usd: 0.05
    max_tool_calls: 1

models:
  allowed:
    - local-small
    - approved-external
  routing:
    public:
      preferred: approved-external
    internal:
      preferred: local-small
    regulated:
      preferred: approved-external
      require_approval: true

rules:
  - id: allow-low-risk-under-budget
    effect: allow
    when:
      risk_in: ["low", "medium"]
      estimated_cost_lte: 0.25

  - id: deny-over-budget
    effect: deny
    when:
      estimated_cost_gt: 0.25

  - id: require-approval-for-high-risk-cost
    effect: require_approval
    when:
      risk_in: ["high", "critical"]
```

## CLI Example

```bash
policyaware risk classify "Analyze 100000 customer records and call tools until complete" --autonomy autonomous
policyaware policy explain policyaware.yaml --prompt "Summarize this small public FAQ"
```

## Python Example

```python
from policyaware import Gateway, GatewayRequest

gateway = Gateway.from_policy_file("policyaware.yaml")

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="analytics-agent",
        user={"id": "u_123", "role": "analyst"},
        context={
            "region": "us",
            "task_type": "analytics",
            "risk": "medium",
            "estimated_cost_usd": 0.10,
        },
        messages=[{"role": "user", "content": "Summarize Q2 public sales trends."}],
    )
)

print(response.policy.decision)
print(response.route.provider)
print(response.token_estimate)
```

## Controls To Use Together

| Risk | Control |
| --- | --- |
| Runaway recursive agents | Tool-call and token caps |
| High-cost prompts | Estimated cost limits |
| Sensitive high-risk work | Approval requirements |
| Vendor sprawl | Approved model list |
| Latency/cost tuning | Model routing policies |

## Related Documentation

- [Model Routing And Providers](../capabilities/model-routing-providers.md)
- [Risk Classification](../capabilities/risk-classification.md)
- [Stateful Session Governance](../stateful-session-governance.md)
- [Observability Templates](../observability-templates.md)
