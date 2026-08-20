# PolicyAware For Antigravity

Use this pack to guide Antigravity agents to apply PolicyAware AI governance workflows inside a local repository.

Copy or reference [ANTIGRAVITY.md](ANTIGRAVITY.md) as the project instruction file for Antigravity sessions.

## First Prompt

```text
Use PolicyAware to scan this repo for LLM, RAG, MCP/tool, PII, secrets, prompt, model-routing, cost, audit, and policy gaps. Create policyaware.yaml and a GitHub Actions scan workflow if missing.
```

## Commands

```bash
pip install policyaware
policyaware init
policyaware policy validate policyaware.yaml
policyaware scan . --format html,json,sarif,markdown
policyaware integrations recommend .
```

## Expected Agent Behavior

- Start with repo inspection.
- Prefer `policyaware scan` as the first value moment.
- Explain findings with file paths, severity, why it matters, and exact fixes.
- Generate YAML and CI files only when useful.
- Keep optional extras opt-in.
- Reuse the standard PolicyAware shield/check icon from `assets/policyaware-icon.svg`.

## Useful Links

- GitHub: https://github.com/ktirupati/policyaware
- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
