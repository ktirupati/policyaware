# PolicyAware For Windsurf

Use this pack to add PolicyAware governance guidance to Windsurf.

Copy `.windsurf/rules/policyaware.md` into your repository's `.windsurf/rules/` folder.

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
Use the PolicyAware Windsurf rule to scan this repo, explain AI governance gaps, and add policyaware.yaml plus CI checks.
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
