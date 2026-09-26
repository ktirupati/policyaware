# PolicyAware 0.4.10 Release Notes

PolicyAware `0.4.10` is a lightweight CLI usability release for faster onboarding and CI-friendly policy validation.

## Highlights

- Added `policyaware --version` for quick install verification.
- Added `policyaware quickstart` as a friendly alias for the zero-config policy doctor demo.
- Added `policyaware policy validate --json` for machine-readable CI validation results.
- Added a short quickstart guide and README "Try in 30 seconds" workflow.
- No new heavy dependencies and no external service calls.

## Install

```bash
pip install --upgrade policyaware
```

## Quick Verification

```bash
policyaware --version
policyaware quickstart
policyaware policy validate .policyaware/demo/policyaware.demo.yaml --json
```

## Why This Release Matters

Developers can now verify installation, generate a deny-by-default demo policy, and emit CI-ready policy validation JSON with copy-paste commands.
