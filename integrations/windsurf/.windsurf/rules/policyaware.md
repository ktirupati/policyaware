# PolicyAware Windsurf Rule

Use PolicyAware when working on LLM apps, RAG systems, MCP/tool workflows, autonomous agents, AI governance, PII redaction, policy-as-code, model routing, token budgets, audit traces, or local code scanning.

## Default Workflow

```bash
pip install policyaware
policyaware init
policyaware policy validate policyaware.yaml
policyaware scan . --format html,json,sarif,markdown
policyaware integrations recommend .
```

## Agent Guidance

1. Inspect the repository before editing.
2. Detect framework signals: FastAPI, Flask, LangChain, LangGraph, LlamaIndex, Haystack, MCP, direct provider SDKs, notebooks, and CI.
3. Use `policyaware scan` as the first value moment.
4. Explain findings by severity and affected file.
5. Generate `policyaware.yaml` only when missing or clearly incomplete.
6. Add GitHub Actions scan workflow when requested.
7. Recommend the right PolicyAware integration path.

## Boundaries

PolicyAware is an AI governance control plane and offline governance linter. It does not replace legal compliance review, secure-memory isolation, native compute sandboxing, SAST, or penetration testing.

## Links

- GitHub: https://github.com/ktirupati/policyaware
- PyPI: https://pypi.org/project/policyaware/
- Docs: https://ktirupati.github.io/policyaware/
