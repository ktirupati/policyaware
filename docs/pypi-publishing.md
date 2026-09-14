# Publishing PolicyAware To PyPI

PolicyAware is configured for PyPI Trusted Publishing through GitHub Actions.

## PyPI Trusted Publisher Values

Use these values on PyPI:

```text
PyPI project name: policyaware
Owner: ktirupati
Repository: policyaware
Workflow filename: publish.yml
Environment name: pypi
```

Use these values on TestPyPI:

```text
PyPI project name: policyaware
Owner: ktirupati
Repository: policyaware
Workflow filename: publish-testpypi.yml
Environment name: testpypi
```

## First Release

1. Create a pending trusted publisher on PyPI.
2. Create a GitHub release for tag `v0.2.0`.
3. Publishing the release triggers `.github/workflows/publish.yml`.
4. PyPI creates the project and publishes the package.

After publication:

```bash
pip install policyaware
```

## TestPyPI

After configuring the TestPyPI pending publisher, run the manual GitHub Actions workflow:

```text
Actions -> Publish Python Package To TestPyPI -> Run workflow
```

Then test install:

```bash
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ policyaware
```

## Version Rule

PyPI does not allow re-uploading the same version. If `0.2.0` is published and you need a fix, update `pyproject.toml` to `0.2.1`.

## Wheel Builds

PolicyAware includes a `cibuildwheel` workflow at:

```text
.github/workflows/wheels.yml
```

Today, the package remains lightweight and pure Python by default. The workflow
is still useful because it verifies installable wheels on Linux, macOS, and
Windows. If PolicyAware later ships an optional Rust, C, or C++ native
accelerator, the same workflow can publish pre-built wheels so users do not need
to compile native code during `pip install policyaware`.

Manual wheel check:

```text
Actions -> Build Wheels -> Run workflow
```
