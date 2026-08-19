# Policy Composition And Hierarchical Overrides

PolicyAware supports hierarchical policy composition for teams that manage AI
governance across many applications, tenants, regions, and agent workflows.

The goal is simple: let platform, compliance, security, and application teams
own separate policy files while still producing one deterministic policy that
the runtime can enforce.

Use this when:

- corporate security owns global AI rules
- compliance teams own healthcare, finance, legal, HR, or EU AI Act rules
- regional teams own data residency requirements
- tenant teams own customer-specific restrictions
- application teams own service-specific tool and model permissions
- local teams need controlled, time-bound experiments

## Problem It Solves

Without composition, teams often copy one large YAML file into every service.
That becomes fragile when emergency permissions, compliance requirements, or
tool rules change.

PolicyAware composition lets you keep policies layered:

```text
global-corporate.yaml
healthcare-hipaa.yaml
us-region.yaml
tenant-acme.yaml
claims-assistant.yaml
local-experiment.yaml
```

Then PolicyAware compiles them into:

```text
policyaware.composed.yaml
```

The composed file is a normal PolicyAware policy. You can validate it, commit it,
publish it to S3/GCS/ADLS/HTTP storage, and load it with
`Gateway.from_policy_file(...)`.

## Precedence Model

PolicyAware composes policy layers in this order:

```text
emergency > global > compliance > region > tenant > app > local_override
```

This answers the enterprise governance question:

> Who wins when a global compliance rule conflicts with a local service rule?

The runtime policy engine still keeps deny-first behavior:

```text
deny -> require_approval -> allow/transform -> default
```

So a local allow cannot bypass a higher-precedence explicit deny.

## Safety Rules

| Rule | Behavior |
| --- | --- |
| Emergency policies have highest precedence | Use emergency layers for immediate fleet-wide revokes or shutdowns. |
| Explicit deny wins | A lower-precedence allow cannot bypass a higher-precedence deny. |
| Local policies may restrict more | App and local layers can add stricter denies, approval requirements, and narrower allows. |
| Broadening exceptions must be explicit | Local broadening requires `allow_broadening: true`, `ticket`, and `expires_at`. |
| Rule names are namespaced | Rules are renamed with their layer prefix, such as `global.corporate.deny_phi_external`. |
| Final output remains standard YAML | The composed policy can be validated and loaded by the normal gateway. |

## Copy-Paste Example

Create `global-corporate.yaml`:

```yaml
id: global_corporate_policy
default: deny

rules:
  - name: deny_secret_leakage
    effect: deny
    when:
      data.contains_secrets: true

  - name: deny_phi_to_external_models
    effect: deny
    when:
      data.contains_phi: true
      request.model_scope: external

  - name: require_approval_for_high_risk
    effect: require_approval
    when:
      risk.tier_in:
        - high
        - critical
```

Create `claims-assistant.yaml`:

```yaml
id: claims_assistant_app_policy
default: deny

rules:
  - name: allow_support_summaries
    effect: allow
    when:
      user.role_in:
        - support_agent
        - claims_adjuster
      request.task_type: summarization
      risk.tier_in:
        - low
        - medium

  - name: redact_pii_for_support
    effect: transform
    action: redact
    when:
      data.contains_pii: true
      user.role: support_agent
```

Create `local-safe-experiment.yaml`:

```yaml
id: local_safe_experiment_policy
default: deny

rules:
  - name: allow_internal_low_risk_research
    effect: allow
    when:
      request.model_scope: internal
      user.role: researcher
      risk.tier: low
```

Create `policy-stack.yaml`:

```yaml
layers:
  - name: corporate
    level: global
    path: global-corporate.yaml

  - name: claims_app
    level: app
    path: claims-assistant.yaml

  - name: safe_local_experiment
    level: local_override
    path: local-safe-experiment.yaml
```

Check the policy stack:

```bash
policyaware policy compose-check policy-stack.yaml
```

Compile the final runtime policy:

```bash
policyaware policy compose policy-stack.yaml --out policyaware.composed.yaml
policyaware policy validate policyaware.composed.yaml
```

Use the composed policy normally:

```python
from policyaware import Gateway

gateway = Gateway.from_policy_file("policyaware.composed.yaml")
```

## Unsafe Override Example

This local policy tries to allow external model use for PHI:

```yaml
id: unsafe_local_experiment
default: deny

rules:
  - name: allow_external_phi_experiment
    effect: allow
    when:
      data.contains_phi: true
      request.model_scope: external
      user.role: researcher
```

Because the global layer denies PHI to external models, `compose-check` reports a
blocked override:

```text
POLICY_COMPOSITION.DENY_OVERRIDE_BLOCKED
```

That is expected. The higher-precedence deny wins.

## Time-Bound Exception Pattern

Sometimes a team needs an approved temporary exception. In that case, the
manifest must make the broadening explicit:

```yaml
layers:
  - name: corporate
    level: global
    path: global-corporate.yaml

  - name: local_phi_experiment
    level: local_override
    path: local-experiment.yaml
    allow_broadening: true
    ticket: SEC-1234
    expires_at: "2026-09-01"
```

PolicyAware records this as a warning:

```text
POLICY_COMPOSITION.BROADENING_EXCEPTION
```

If `allow_broadening: true` is used without both `ticket` and `expires_at`,
strict composition fails with:

```text
POLICY_COMPOSITION.EXCEPTION_METADATA_REQUIRED
```

## Python API

Use the API when you want to compose policies inside a platform tool, CI helper,
or deployment workflow:

```python
from pathlib import Path
import yaml

from policyaware import PolicyComposer
from policyaware.policy_composition import load_policy_layers

layers = load_policy_layers("policy-stack.yaml")
report = PolicyComposer(strict=True).compose(layers)

print(report.has_errors)
for finding in report.findings:
    print(finding.severity, finding.code, finding.message)

if report.has_errors:
    raise SystemExit("Policy composition failed")

Path("policyaware.composed.yaml").write_text(
    yaml.safe_dump(report.composed_policy, sort_keys=False),
    encoding="utf-8",
)
```

Then load it:

```python
from policyaware import Gateway, GatewayRequest

gateway = Gateway.from_policy_file("policyaware.composed.yaml")

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="claims-assistant",
        user={"id": "u-123", "role": "claims_adjuster"},
        context={
            "region": "us",
            "task_type": "summarization",
            "risk": "low",
            "model_scope": "internal",
        },
        messages=[{"role": "user", "content": "Summarize this claim."}],
    )
)

print(response.policy.decision)
print(response.policy.reason_codes)
```

## CI/CD Example

For GitHub-native scanning, use the official action:

```yaml
- uses: actions/checkout@v4
- uses: ktirupati/policyaware-action@v1
```

For full policy CI/CD, add composition and contract checks:

```yaml
name: PolicyAware Policy CI

on:
  pull_request:

jobs:
  policyaware:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install policyaware
      - run: policyaware policy validate policyaware.yaml
      - run: policyaware policy compose-check policy-stack.yaml
      - run: policyaware policy compose policy-stack.yaml --out policyaware.composed.yaml
      - run: policyaware policy validate policyaware.composed.yaml
      - run: policyaware contract check ./src --policy tool-governance.yaml --fail-on high
      - run: policyaware scan ./src --format html,json,sarif,markdown --fail-on high
```

## Recommended Enterprise Pattern

Use this structure for distributed fleets:

```text
central policy source
  emergency-revoke.yaml
  global-corporate.yaml
  compliance/healthcare.yaml
  region/us.yaml
  tenant/acme.yaml

service repository
  app-policy.yaml
  local-experiment.yaml
  policy-stack.yaml
  policyaware.composed.yaml
```

Recommended controls:

- run `compose-check` on every pull request
- compile the final policy before deployment
- validate the composed policy
- publish composed policies to central storage only after CI passes
- keep emergency policies in the highest-precedence layer
- require ticket and expiry for any local broadening
- keep `default: deny`
- export SARIF and scan reports for compliance review

## Included Runnable Example

The repository includes a ready-to-run example:

```bash
policyaware policy compose-check examples/policy-composition/policy-stack.yaml

policyaware policy compose \
  examples/policy-composition/policy-stack-safe.yaml \
  --out policyaware.composed.yaml \
  --force

policyaware policy validate policyaware.composed.yaml
```

The unsafe stack fails because a local experiment tries to allow an action that
overlaps a global deny. The safe stack composes successfully because it only adds
a narrower internal-model allow.
