# PolicyAware For Cursor

Use this pack to add PolicyAware governance guidance to Cursor.

Copy `.cursor/rules/policyaware.mdc` into your repository's `.cursor/rules/` folder.

## Commands

```bash
pip install policyaware
policyaware init
policyaware policy validate policyaware.yaml
policyaware scan . --format html,json,sarif,markdown
policyaware integrations recommend .
```

## First Prompt

```text
Use the PolicyAware Cursor rule to scan this repo, explain AI governance gaps, and add policyaware.yaml plus CI checks.
```

## Shared Icon

Use:

```text
assets/policyaware-icon.svg
```

## Useful Links

- GitHub: https://github.com/ktirupati/policyaware
- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
