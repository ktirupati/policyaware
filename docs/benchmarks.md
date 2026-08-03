# Lightweight Benchmarks

PolicyAware includes benchmark guidance so maintainers and users can measure local governance overhead before production rollout.

These benchmarks are intentionally simple and local. They do not call external model providers.

## Benchmark Targets

| Area | What To Measure | Why It Matters |
| --- | --- | --- |
| Data protection | `DataProtectionEngine.inspect(...)` over representative prompts | Sensitive-data checks should be fast enough for request-time use. |
| Policy decision | `PolicyEngine.decide(...)` over common contexts | Deny-by-default policy should add low overhead. |
| Tool governance | `ToolPolicyEngine.decide(...)` over connector/action calls | Agent tool checks should be cheap enough to run before every tool call. |
| Local scan | `policyaware scan ./repo` | Pre-deployment governance scanning should remain practical for developer and CI usage. |
| Evidence export | `to_agt_*` helpers | Audit/evidence conversion should be near-zero overhead. |

## Copy-Paste Benchmark Script

```python
from time import perf_counter

from policyaware import (
    DataProtectionEngine,
    GatewayRequest,
    PolicyEngine,
    RiskClassifier,
    ToolCallRequest,
    ToolPolicyEngine,
)

policy = PolicyEngine.from_file("examples/policies/basic.yaml")
tool_policy = ToolPolicyEngine.from_file("examples/policies/tool-governance.yaml")
data = DataProtectionEngine()
risk_classifier = RiskClassifier()

request = GatewayRequest(
    tenant="acme",
    app="bench",
    user={"id": "u_1", "role": "support_agent"},
    context={"region": "us", "risk": "low", "task_type": "support"},
    messages=[{"role": "user", "content": "Email jane@example.com about this case."}],
)

N = 1000

start = perf_counter()
for _ in range(N):
    findings = data.inspect(request.prompt_text)
print("data_protection_ms=", round((perf_counter() - start) * 1000 / N, 4))

findings = data.inspect(request.prompt_text)
risk = risk_classifier.classify(request, findings)

start = perf_counter()
for _ in range(N):
    policy.decide(request, findings, risk)
print("policy_decision_ms=", round((perf_counter() - start) * 1000 / N, 4))

tool_request = ToolCallRequest(
    agent_id="code_assistant",
    connector_id="github",
    action="create_pr",
    user={"role": "developer"},
)

start = perf_counter()
for _ in range(N):
    tool_policy.decide(tool_request)
print("tool_decision_ms=", round((perf_counter() - start) * 1000 / N, 4))
```

## Scan Timing

```bash
policyaware scan ./my-ai-app --format html,json
```

The terminal dashboard reports total scan time, files scanned, and findings.

## Notes

- Base PolicyAware checks are rules-based and local.
- Optional ML integrations such as Presidio, Transformers, Torch, or ONNX can add model-load time and higher runtime overhead.
- Run benchmarks on representative repositories and prompts before setting CI thresholds.
