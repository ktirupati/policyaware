# PolicyAware 0.4.9 Release Notes

PolicyAware `0.4.9` is a small hardening release for the zero-config policy doctor demo.

## Highlights

- Improved `policyaware demo doctor` overwrite handling so the message is stable across Linux, macOS, and Windows CLI test environments.
- Keeps the `0.4.8` onboarding demo behavior: create a tiny deny-by-default policy and run the real policy doctor report locally.
- No new heavy dependencies and no external service calls.

## Install

```bash
pip install --upgrade policyaware
```

## Quick Verification

```bash
policyaware demo doctor
policyaware demo doctor --json
policyaware demo doctor --force
```

## Why This Release Matters

The package remains lightweight while making first-run demo behavior more predictable across local machines and CI systems.
