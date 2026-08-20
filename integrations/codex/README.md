# PolicyAware For Codex

Use PolicyAware inside Codex as an AI governance reviewer for LLM, RAG, MCP/tool, and autonomous-agent repositories.

The local Codex plugin lives outside this repository during development:

```text
C:\Users\kktir\plugins\policyaware
```

The plugin uses the same standard icon:

```text
assets/policyaware-icon.svg
```

## Recommended First Prompt

```text
Use PolicyAware to scan this repository, explain governance gaps, create a starter policyaware.yaml if missing, and add a GitHub Actions scan workflow.
```

## Commands

```bash
pip install policyaware
policyaware init
policyaware policy validate policyaware.yaml
policyaware scan . --format html,json,sarif,markdown
policyaware integrations recommend .
```

## What Codex Should Do

1. Inspect the repository structure with `rg --files`.
2. Detect AI frameworks and direct provider calls.
3. Check whether `policyaware` is installed.
4. Run `policyaware scan`.
5. Explain the highest-risk findings first.
6. Create or improve `policyaware.yaml`.
7. Add `.github/workflows/policyaware-scan.yml`.
8. Recommend FastAPI, LangChain, LlamaIndex, LangGraph, Haystack, MCP/tool, sidecar, privacy, ML, guardrails, routing, or audit integration paths.

## Useful Links

- GitHub: https://github.com/ktirupati/policyaware
- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
- Scan docs: https://github.com/ktirupati/policyaware/blob/main/docs/local-code-scan.md
