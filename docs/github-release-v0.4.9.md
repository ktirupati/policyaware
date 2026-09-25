# GitHub Release Draft: PolicyAware 0.4.9

Use this as the GitHub Releases body for tag `v0.4.9`.

## PolicyAware 0.4.9

PolicyAware `0.4.9` is a small hardening release for the zero-config policy doctor demo.

### Highlights

- Improved `policyaware demo doctor` overwrite handling so the message is stable across Linux, macOS, and Windows CLI test environments.
- Keeps the zero-config onboarding workflow introduced in `0.4.8`.
- No new heavy dependencies and no external service calls.

### Install

```bash
pip install --upgrade policyaware
```

### Try The Demo

```bash
policyaware demo doctor
policyaware demo doctor --json
policyaware demo doctor --force
```

### Links

- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
- CLI usability: https://github.com/ktirupati/policyaware/blob/main/docs/cli-usability.md
- GitHub Wiki: https://github.com/ktirupati/policyaware/wiki
