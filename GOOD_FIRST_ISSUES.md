# Good First Issues

This page lists starter tasks for new PolicyAware contributors.

If you want to work on one, open a GitHub issue or comment on an existing one:

https://github.com/ktirupati/policyaware/issues

## Documentation

1. Add a copy-paste policy YAML for a retail customer support copilot.
2. Add a copy-paste policy YAML for an HR assistant with PII redaction.
3. Add a short tutorial for `policyaware feedback` and `policyaware about`.
4. Add screenshots or terminal output for `policyaware scan`.
5. Add a FAQ section for local code scanning.

## Examples

6. Add a minimal Flask example using PolicyAware policy checks.
7. Add a LlamaIndex RAG example with citation evaluation.
8. Add a notebook example showing `DataProtectionEngine`.
9. Add a GitHub Actions example that uploads the HTML scan report as an artifact.
10. Add a local Ollama routing example.

## Scanner Rules

11. Add a scan rule for missing max iteration limits in agent code.
12. Add a scan rule for direct vector store retrieval without source metadata.
13. Add a scan rule for prompts saved in fixtures with sensitive data.
14. Add a scan rule for missing approval policy around write/delete tool actions.
15. Add a scan rule for provider calls without timeout or retry limits.

## Tests

16. Add tests for additional YAML policy schema validation errors.
17. Add tests for scan suppression edge cases.
18. Add tests for Markdown report output.
19. Add tests for CLI help output.
20. Add tests for custom guardrail adapter examples.

## Contributor Notes

Good first issues should:

- be small
- include tests or docs
- avoid new required dependencies
- avoid real credentials
- avoid private data

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions.
