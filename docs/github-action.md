# Official GitHub Action

`ktirupati/policyaware-action` is the official GitHub Actions integration for
PolicyAware. The Action is intentionally a thin adapter: it installs a tested
PolicyAware release, invokes `policyaware scan`, emits GitHub annotations, and
optionally uploads SARIF and report artifacts.

```yaml
- uses: actions/checkout@v6
- uses: ktirupati/policyaware-action@v1
```

Scanner behavior, rules, report schemas, baselines, and configuration remain
owned by this repository. The Action has an independent release lifecycle and
must verify a published PolicyAware package before advancing its tested default.

Release order:

1. Test and publish PolicyAware to PyPI.
2. Verify the installed CLI from PyPI.
3. Update and test `policyaware-action` against that exact release.
4. Publish the Action and Marketplace release.

The PolicyAware package never depends on or publishes the Action.
