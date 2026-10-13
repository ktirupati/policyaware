# PolicyAware 0.4.11

PolicyAware 0.4.11 adds clearer policy provenance and an easy way to gate deployments against an approved policy fingerprint.

## Policy Fingerprints

Print the canonical policy fingerprint as JSON:

```bash
policyaware policy fingerprint policyaware.yaml --json
```

Compare against an approved SHA-256 value in CI:

```bash
policyaware policy fingerprint policyaware.yaml \
  --expected-sha256 "$APPROVED_POLICY_SHA256" \
  --json
```

The command validates the policy first. A mismatch returns a nonzero exit status and reports `matches_expected: false`. Fingerprints identify policy content; they are not signatures or approval attestations.

Policy decisions and audit traces now include the policy ID, optional `policy_version`, schema version, and canonical SHA-256 when the decision originates from a policy engine.

## Audit Snapshot Privacy

`AuditLogger` and `SQLiteAuditLogger` accept `snapshot_mode="metadata"` to omit raw prompt/output bodies and arbitrary request/response payloads from snapshots. Trace-level identifiers and compact policy-decision metadata remain. The default remains `full` for backward compatibility; assess identifier sensitivity, access controls, and retention for either mode.

## CLI And Documentation

- Added `policyaware quickstart --no-write` for a non-mutating onboarding preview.
- Added strict policy validation and GitHub Actions annotation output.
- Added compact examples listing for scripts.
- Clarified product capability boundaries and technical-evidence limitations in the docs and Wiki.

## Verification

The release was checked with the full test suite and Ruff. See the repository's changelog for details.
