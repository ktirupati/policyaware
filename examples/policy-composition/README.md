# Policy Composition And Hierarchical Overrides

This runnable example shows how PolicyAware composes distributed enterprise
policies while keeping override behavior predictable.

Use this when a corporate team owns global compliance rules while application
teams own service-specific AI rules.

## Files

| File | Purpose |
| --- | --- |
| `global-corporate.yaml` | Global deny and approval rules owned by platform/security. |
| `app-service.yaml` | Claims assistant rules owned by the application team. |
| `local-experiment.yaml` | Unsafe local experiment that tries to broaden access. |
| `local-safe-experiment.yaml` | Safe local experiment that only allows low-risk internal model use. |
| `policy-stack.yaml` | Unsafe stack used to demonstrate deny-wins protection. |
| `policy-stack-safe.yaml` | Safe stack that can be compiled into a runtime policy. |

## Precedence

PolicyAware composes layers in this order:

```text
emergency > global > compliance > region > tenant > app > local_override
```

The final composed policy still uses normal PolicyAware semantics:

```text
deny -> require_approval -> allow/transform -> default
```

So an explicit deny from a higher-precedence layer cannot be bypassed by a local
allow.

## Test The Unsafe Stack

```bash
policyaware policy compose-check examples/policy-composition/policy-stack.yaml
```

Expected result: the command fails because `local-experiment.yaml` tries to
allow external model use for PHI, which overlaps the global
`deny_phi_to_external_models` rule.

Expected reason code:

```text
POLICY_COMPOSITION.DENY_OVERRIDE_BLOCKED
```

## Compose A Safe Stack

```bash
policyaware policy compose \
  examples/policy-composition/policy-stack-safe.yaml \
  --out policyaware.composed.yaml \
  --force

policyaware policy validate policyaware.composed.yaml
```

The safe stack adds a local allow for low-risk internal experimentation without
broadening the protected global deny.

## Use The Composed Policy

```python
from policyaware import Gateway

gateway = Gateway.from_policy_file("policyaware.composed.yaml")
```

The generated `policyaware.composed.yaml` is a normal PolicyAware YAML policy.
You can validate it, commit it, publish it to central policy storage, or load it
from local runtime services.

## Exception Pattern

Use `allow_broadening: true` only when an exception is intentional, approved, and
time-bound.

```yaml
layers:
  - name: local_phi_experiment
    level: local_override
    path: local-experiment.yaml
    allow_broadening: true
    ticket: SEC-1234
    expires_at: "2026-09-01"
```

PolicyAware records this as a warning in the composition report. Organizations
should pair this pattern with signed policy bundles, emergency revokes, and
audit trace review.
