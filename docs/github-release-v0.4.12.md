# PolicyAware 0.4.12

PolicyAware 0.4.12 adds a dependency-light policy lockfile workflow for reviewable policy provenance and CI drift detection.

```bash
policyaware policy lock create policyaware.yaml --out policyaware.lock.json
policyaware policy lock verify policyaware.yaml --lock-file policyaware.lock.json --json
```

The command validates the policy before creating or verifying the lock. Verification returns a nonzero exit status when its canonical fingerprint has changed. Lockfiles are unsigned and should be protected through normal repository review and access controls.

```bash
pip install --upgrade policyaware
```

See [release notes](release-notes-0.4.12.md), [CLI usability](cli-usability.md), and [audit and observability](capabilities/audit-observability.md).
