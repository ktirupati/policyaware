# GitHub Release Draft: PolicyAware 0.4.10

Use this as the GitHub Releases body for tag `v0.4.10`.

## PolicyAware 0.4.10

PolicyAware `0.4.10` is a lightweight CLI usability release for faster onboarding and CI-friendly policy validation.

### Highlights

- Added `policyaware --version` for quick install verification.
- Added `policyaware quickstart` as a friendly alias for the zero-config policy doctor demo.
- Added `policyaware policy validate --json` for machine-readable CI validation results.
- Added a short quickstart guide and README "Try in 30 seconds" workflow.
- No new heavy dependencies and no external service calls.

### Install

```bash
pip install --upgrade policyaware
```

### Try It

```bash
policyaware --version
policyaware quickstart
policyaware policy validate .policyaware/demo/policyaware.demo.yaml --json
```

### Links

- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
- Quickstart: https://github.com/ktirupati/policyaware/blob/main/docs/quickstart.md
- CLI usability: https://github.com/ktirupati/policyaware/blob/main/docs/cli-usability.md
- GitHub Wiki: https://github.com/ktirupati/policyaware/wiki
