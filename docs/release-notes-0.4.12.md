# PolicyAware 0.4.12

PolicyAware 0.4.12 adds a reviewable policy lockfile workflow built on the canonical policy fingerprint introduced in 0.4.11.

## Create And Verify A Policy Lock

Create a JSON lockfile after validating the policy:

```bash
policyaware policy lock create policyaware.yaml --out policyaware.lock.json
```

Commit the policy and lockfile together, then verify the pin in CI before deployment:

```bash
policyaware policy lock verify policyaware.yaml \
  --lock-file policyaware.lock.json \
  --json
```

Verification exits nonzero if the policy content differs from the approved lock. The generated lockfile is deterministic and is not overwritten unless `--force` is supplied. It is unsigned metadata, so review and protect it like other policy source files.

## Verification

The release was checked with the full test suite and Ruff. See the repository changelog for details.
