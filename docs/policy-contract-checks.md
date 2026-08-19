# Policy Contract Checks

Policy-as-code is powerful only when YAML policies stay synchronized with application code and tool schemas.

PolicyAware includes a contract checker to detect policy drift between MCP/tool governance YAML and Python tool implementations.

## Problem It Solves

If a Python tool changes from:

```python
def update_customer(customer_id: str, email: str):
    ...
```

to:

```python
def update_customer(account_id: str, email_address: str):
    ...
```

but YAML still references:

```yaml
arguments.customer_id: "cust_123"
```

then the policy can become stale. The YAML may still be valid, but runtime matching can block unexpectedly or miss an intended condition.

## CLI

```bash
policyaware contract check ./src --policy tool-governance.yaml
policyaware contract check ./src --policy tool-governance.yaml --json
policyaware contract export ./src --out policyaware-tool-contracts.json
```

Runnable local example:

```bash
policyaware contract check examples/policy-contract-checks --policy examples/policy-contract-checks/tool-governance.yaml
```

## Naming Conventions

The checker maps YAML connector/actions to Python functions using:

```text
<action>
<connector>_<action>
<connector>__<action>
```

For example:

```yaml
connectors:
  - id: crm
    actions:
      update_customer:
        effect: require_approval
        when:
          arguments.customer_id: "cust_123"
```

matches:

```python
def crm_update_customer(customer_id: str):
    ...
```

or:

```python
def crm__update_customer(customer_id: str):
    ...
```

## Decorated Tool Contracts

You can also mark functions explicitly:

```python
@policyaware_tool(connector_id="crm", action="update_customer")
def update_customer(account_id: str):
    ...
```

The checker reads the decorator statically. The decorator does not need to execute during scanning.

## CI Workflow Example

For GitHub-native pull-request scanning, use the official
[`ktirupati/policyaware-action`](https://github.com/ktirupati/policyaware-action).
For deeper policy CI/CD, combine the action with the CLI commands below.

Copy `examples/ci/policyaware-contract-check.yml` into `.github/workflows/policyaware-contract-check.yml` and adjust file paths for your project:

```yaml
name: PolicyAware Governance Checks

on:
  pull_request:

jobs:
  policyaware:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install PolicyAware
        run: pip install policyaware
      - name: Validate YAML policies
        run: policyaware policy validate policyaware.yaml
      - name: Check policy/tool contract drift
        run: policyaware contract check ./src --policy tool-governance.yaml --fail-on high
      - name: Scan code governance risks
        run: policyaware scan ./src --format html,json,sarif,markdown --fail-on high
```

This makes YAML policy drift a normal pull-request failure, not a production surprise.

For hierarchical policies, add composition checks before publishing a policy
bundle to central storage:

```bash
policyaware policy compose-check policy-stack.yaml
policyaware policy compose policy-stack.yaml --out policyaware.composed.yaml
policyaware policy validate policyaware.composed.yaml
```

## What It Checks

| Check | Example Finding |
| --- | --- |
| Missing implementation | YAML has `github.create_pr`, but no matching Python function exists. |
| Stale argument reference | YAML references `arguments.customer_id`, but the Python function accepts `account_id`. |
| Matching contract | YAML action and referenced arguments match a Python function signature. |

## Python API

```python
from policyaware import PolicyContractChecker

report = PolicyContractChecker().check("./src", "tool-governance.yaml")

print(report.passed)
for finding in report.findings:
    print(finding.severity, finding.connector_id, finding.action, finding.title)
```

## Recommended Release Gate

Use this in CI with the scanner:

```bash
policyaware policy validate policyaware.yaml
policyaware policy validate tool-governance.yaml
policyaware contract check ./src --policy tool-governance.yaml --fail-on high
policyaware scan ./src --format html,json,sarif,markdown --fail-on high
```

This prevents policy drift from silently reaching production.
