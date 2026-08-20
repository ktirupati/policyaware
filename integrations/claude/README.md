# PolicyAware For Claude Code

Use this pack to guide Claude Code toward PolicyAware governance workflows for LLM, RAG, MCP/tool, and autonomous-agent repositories.

Copy [CLAUDE.md](CLAUDE.md) into a repository or reference it during Claude Code sessions.

## First Prompt

```text
Follow the PolicyAware instructions in CLAUDE.md. Scan this repository, identify AI governance risks, explain the top findings, and create policyaware.yaml plus CI checks if missing.
```

## Commands

```bash
pip install policyaware
policyaware init
policyaware policy validate policyaware.yaml
policyaware scan . --format html,json,sarif,markdown
policyaware integrations recommend .
```

## Shared Icon

Use the standard icon:

```text
assets/policyaware-icon.svg
```

## Useful Links

- GitHub: https://github.com/ktirupati/policyaware
- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
