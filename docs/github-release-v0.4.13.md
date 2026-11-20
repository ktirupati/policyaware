# PolicyAware 0.4.13

PolicyAware 0.4.13 adds `policyaware policy lock update` to safely refresh approved policy fingerprints.

```bash
policyaware policy lock update policyaware.yaml \
  --lock-file policyaware.lock.json \
  --force \
  --json
```

The command requires explicit `--force`, validates the current lock and policy, atomically writes the new provenance, and reports the previous and updated SHA-256 values. The lockfile is unsigned and should remain subject to normal repository review.

```bash
pip install --upgrade policyaware
```

See [release notes](release-notes-0.4.13.md), [CLI usability](cli-usability.md), and [audit and observability](capabilities/audit-observability.md).
