# /policyaware:scan

Run PolicyAware's offline AI governance scanner for the current repository.

## Purpose

Use this command to find LLM, RAG, MCP/tool, agent, PII, PHI, secrets, prompt, provider, routing, cost, audit, and policy gaps before deployment.

## Command

```bash
pip install policyaware
policyaware scan . --format html,json,sarif,markdown
```

For pull-request style blocking:

```bash
policyaware scan . --format html,json,sarif,markdown --fail-on high
```

## Expected Claude Behavior

1. Check whether `policyaware` is installed.
2. Run the scan if tools are available.
3. Summarize the highest severity findings first.
4. Identify generated reports:
   - `policyaware-scan-report.html`
   - `policyaware-scan-report.json`
   - `policyaware-scan-report.sarif`
   - `policyaware-scan-report.md`
5. Suggest concrete fixes with file paths, YAML, and code snippets.
6. Recommend `policyaware init` or `policyaware integrations recommend .` when appropriate.

## Boundaries

Do not treat the scan as a replacement for SAST, dependency scanning, penetration testing, or legal compliance review. Present it as an offline AI governance linter.
