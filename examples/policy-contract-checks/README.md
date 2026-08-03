# Policy Contract Checks Example

This example shows how PolicyAware prevents drift between MCP/tool governance YAML and Python tool code.

## Why This Matters

Policy files often reference tool arguments:

```yaml
arguments.customer_id: "cust_123"
```

If the Python function later changes from `customer_id` to `account_id`, the YAML may still parse correctly but no longer describes the real tool contract. `policyaware contract check` catches that before production.

## Run It

From the repository root:

```bash
policyaware contract check examples/policy-contract-checks --policy examples/policy-contract-checks/tool-governance.yaml
```

Expected result:

```text
PolicyAware Contract Check
Passed: True
```

## Try A Drift Failure

Edit `tools.py` and rename `customer_id` to `account_id`, then run the same command again.

Expected result:

```text
YAML argument reference is not present in Python function signature.
```

## CI Pattern

Use this as a release gate:

```bash
policyaware policy validate tool-governance.yaml
policyaware contract check ./src --policy tool-governance.yaml --fail-on high
policyaware scan ./src --format html,json,sarif,markdown --fail-on high
```

