# PolicyAware 0.4.13

PolicyAware 0.4.13 adds an explicit, reviewable workflow for refreshing an approved policy lock after intentional policy changes.

## Update A Policy Lock

After reviewing a policy change, update its existing lockfile:

```bash
policyaware policy lock update policyaware.yaml \
  --lock-file policyaware.lock.json \
  --force \
  --json
```

The command requires `--force`, validates the existing lock and updated policy, atomically writes the refreshed lockfile, and reports both `previous_sha256` and `updated_sha256`. It also reports `changed: false` when the policy fingerprint is unchanged. Verification remains:

```bash
policyaware policy lock verify policyaware.yaml --lock-file policyaware.lock.json --json
```

Lockfiles are unsigned metadata; review and protect them like other policy source files.

## Verification

The release was checked with the full test suite and Ruff. See the repository changelog for details.
