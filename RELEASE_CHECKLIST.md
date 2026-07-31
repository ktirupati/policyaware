# PolicyAware Release Checklist

Use this checklist before publishing a new PolicyAware release to GitHub and PyPI.

## 1. Confirm Version And Changelog

- Update `pyproject.toml` version.
- Move completed changelog items from `Unreleased` into the target version section.
- Confirm author metadata remains `Krishna Kishor Tirupati`.
- Confirm project URLs point to GitHub, GitHub Pages docs, PyPI, issues, discussions, and feedback form.

## 2. Run Local Quality Checks

```bash
python -m pytest -q
python -m ruff check src tests
```

## 3. Check Documentation Links

Verify important local docs and wiki links before pushing:

```bash
python scripts/check_docs_links.py
```

If a dedicated script is not available, run the local link-check snippet used during release preparation or manually review README, docs index, sitemap, and wiki sidebar.

## 4. Build Distribution Artifacts

```bash
python -m build
python -m twine check dist/*
```

Confirm the newest files exist:

```bash
dir dist
```

Expected files:

```text
policyaware-X.Y.Z-py3-none-any.whl
policyaware-X.Y.Z.tar.gz
```

## 5. Smoke Test The Built Wheel

Create a clean temporary virtual environment and install the built wheel:

```bash
python -m venv .tmp-release-venv
.tmp-release-venv\Scripts\python -m pip install --upgrade pip
.tmp-release-venv\Scripts\python -m pip install dist\policyaware-X.Y.Z-py3-none-any.whl
```

Run basic commands:

```bash
.tmp-release-venv\Scripts\policyaware about
.tmp-release-venv\Scripts\policyaware init --out .tmp-release-policy.yaml --force
.tmp-release-venv\Scripts\policyaware policy validate .tmp-release-policy.yaml
.tmp-release-venv\Scripts\policyaware scan . --format html,json --out .tmp-release-scan.html --json .tmp-release-scan.json
```

Clean temporary smoke-test files after review.

## 6. Review Package Contents

Inspect the wheel and source distribution:

```bash
python -m zipfile --list dist\policyaware-X.Y.Z-py3-none-any.whl
tar -tf dist\policyaware-X.Y.Z.tar.gz
```

Confirm:

- `policyaware` package modules are included.
- no secrets, local temp files, notebooks with private data, or credentials are included.
- README renders successfully in `twine check`.
- scan preview assets are present in the repository before PyPI publish, because README uses GitHub raw image URLs.

## 7. Commit And Push

Only after review approval:

```bash
git status
git add .
git commit -m "Release policyaware X.Y.Z"
git push origin main
```

Push the local wiki repository separately if wiki docs changed:

```bash
cd ../policyaware.wiki
git status
git add .
git commit -m "Update PolicyAware wiki for X.Y.Z"
git push origin master
```

## 8. Publish To PyPI

Use the configured GitHub Actions trusted publisher workflow.

Recommended:

1. Confirm the GitHub workflow file is present under `.github/workflows/publish.yml`.
2. Confirm PyPI trusted publisher uses:
   - repository: `policyaware`
   - workflow: `publish.yml`
   - project: `policyaware`
3. Trigger the workflow from GitHub Actions.
4. Verify the new version appears at https://pypi.org/project/policyaware/.

## 9. Post-Release Verification

```bash
pip install --upgrade policyaware
policyaware about
policyaware init --out policyaware.yaml --force
policyaware policy validate policyaware.yaml
```

Also verify:

- GitHub README renders correctly.
- GitHub Pages docs are live.
- GitHub Wiki pages are live.
- PyPI long description renders acceptably.
- Google/Bing sitemap URLs remain valid.

## 10. Release Announcement

Post a short release note to:

- GitHub Releases
- GitHub Discussions
- Dev.to or Medium if the release includes user-facing features
- LinkedIn

Include:

- top features
- install command
- one quick example
- docs link
- feedback/testimonial link
