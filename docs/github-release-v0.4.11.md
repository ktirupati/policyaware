# PolicyAware 0.4.11

PolicyAware 0.4.11 adds policy provenance, a CI fingerprint gate, and configurable audit snapshot minimization.

## Highlights

- Run `policyaware policy fingerprint policyaware.yaml --json` to print validated policy identity and its canonical SHA-256.
- Add `--expected-sha256 "$APPROVED_POLICY_SHA256"` to fail CI when the policy differs from the approved fingerprint.
- Policy decisions and audit traces carry policy ID, optional policy version, schema version, and configuration fingerprint when applicable.
- Set `snapshot_mode="metadata"` on `AuditLogger` or `SQLiteAuditLogger` to omit raw prompt/output and arbitrary payload snapshots. The default `full` mode is retained for backward compatibility.
- Adds strict validation/GitHub annotations, non-writing quickstart preview, and compact example listing.

## Install

```bash
pip install --upgrade policyaware
```

## Documentation

- [Release notes](release-notes-0.4.11.md)
- [Audit and observability](capabilities/audit-observability.md)
- [CLI usability](cli-usability.md)
- [Capabilities and boundaries](capability-boundaries.md)
