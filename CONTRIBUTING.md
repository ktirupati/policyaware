# Contributing To PolicyAware

Thank you for your interest in contributing to PolicyAware.

PolicyAware is an open-source Python framework for governed LLM, RAG, MCP/tool, and AI-agent execution. Contributions are welcome across code, tests, docs, examples, policies, scan rules, and issue reports.

## Ways To Contribute

- Report bugs.
- Request features.
- Share real use cases.
- Improve documentation.
- Add examples.
- Add tests.
- Improve local code scan rules.
- Add policy templates.
- Improve provider or guardrails integration examples.

## Development Setup

```bash
git clone https://github.com/ktirupati/policyaware.git
cd policyaware
pip install -e ".[dev]"
pytest
ruff check src tests
```

## Local Validation

Before opening a pull request, run:

```bash
pytest -q
ruff check src tests
python -m compileall src tests examples
python -m build
python -m twine check dist/policyaware-*
```

## Contribution Guidelines

- Keep changes focused and small when possible.
- Add or update tests for behavior changes.
- Add documentation for new public APIs, CLI commands, scan rules, or YAML fields.
- Keep default behavior deterministic and lightweight.
- Do not add mandatory heavy ML dependencies to the base package.
- Do not include secrets, private prompts, customer data, PHI, PII, or proprietary information in issues, tests, examples, or docs.

## Scan Rule Contributions

For new `policyaware scan` rules, include:

- What risk the rule detects.
- Example code that should trigger the rule.
- Example code that should not trigger the rule.
- Severity recommendation.
- Remediation guidance.
- Tests in `tests/test_scanner.py` or a focused scanner test file.

## Documentation Contributions

Useful documentation contributions include:

- Copy-paste YAML policies.
- Realistic Python examples.
- CI examples.
- Provider configuration examples.
- MCP/tool governance examples.
- Evaluation examples.
- Audit/report screenshots or terminal output.

## Feedback And Testimonials

If you use PolicyAware, please share feedback:

- Private structured feedback form: https://docs.google.com/forms/d/e/1FAIpQLSc2QcQydjXZ0YF9bbVSpudoM5y8noxIP5jU-acVmjlyvf6Slg/viewform
- GitHub Discussions: https://github.com/ktirupati/policyaware/discussions
- Testimonials and Show and Tell: https://github.com/ktirupati/policyaware/discussions/categories/show-and-tell

Please do not share secrets, private prompts, PHI, PII, customer data, or confidential internal details.

## Maintainer

PolicyAware is created and maintained by Krishna Kishor Tirupati.

- GitHub: https://github.com/ktirupati
- LinkedIn: https://www.linkedin.com/in/krishna-tirupati/
