# Enterprise AI Control Plane Demo

This demo shows PolicyAware as a full AI governance control plane:

- prompt inspection
- PII redaction
- risk classification
- deny-by-default YAML policy enforcement
- model routing
- runtime evaluation
- MCP/tool governance
- audit trace creation
- Microsoft AGT-style evidence export

## Install

```bash
pip install policyaware
```

## Run

```bash
python control_plane_demo.py
```

## Expected Output

```text
policy_decision= conditional_allow
risk_tier= medium
route_model= local/sim-small
evals= ['sensitive_data_leakage', 'policy_compliance']
tool_decision= deny
gateway_evidence_decision= permit
tool_evidence_decision= deny
```

Use this example when you want to show PolicyAware as more than a content filter: it governs prompts, context, model routing, tools, evaluations, and audit evidence together.
