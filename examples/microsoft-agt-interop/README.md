# Microsoft AGT-Style Interop

This example shows how to export PolicyAware tool-governance decisions as Microsoft Agent Governance Toolkit-style evidence JSON.

PolicyAware does not require Microsoft Agent Governance Toolkit as a dependency. The exported schema is labeled as PolicyAware interop evidence and is not an official Microsoft-owned wire contract.

## Install

```bash
pip install policyaware
```

For local development from this repository:

```bash
pip install -e ".[dev]"
```

## Run

```bash
python agt_interop_demo.py
```

## Expected Output

```text
read_customer_decision=permit
read_customer_policyaware_decision=allow
read_customer_approval_required=False
update_customer_decision=review
update_customer_policyaware_decision=require_approval
update_customer_approval_required=True
delete_customer_decision=deny
delete_customer_policyaware_decision=deny
delete_customer_approval_required=False
```

The generated evidence JSON includes:

- schema and evidence id
- PolicyAware decision
- AGT-style outcome: `permit`, `review`, or `deny`
- enforcement flags
- agent id, tenant, user, connector, action, and arguments
- matched rules and reason codes

Use this pattern when your enterprise wants PolicyAware to govern model/tool execution while also exporting normalized evidence into a broader agent governance workflow.
