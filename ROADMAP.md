# PolicyAware Roadmap

PolicyAware is an open-source policy-aware control plane for governed LLM, RAG, MCP/tool, and AI-agent applications.

This roadmap lists practical work that can improve adoption, enterprise usefulness, and contributor participation.

## Current Focus

- Deny-by-default policy enforcement for AI application requests.
- PII, PHI, secrets, and sensitive-data detection and redaction.
- Local AI governance code scanning with HTML, JSON, SARIF, and Markdown reports.
- MCP/tool governance for connector-level and action-level permissions.
- Model routing across local and external providers.
- Runtime evaluation, audit traces, and compliance evidence.
- Optional ML signals and guardrails integrations.
- Feedback and testimonial collection through GitHub Discussions and the PolicyAware feedback form.

## Next 30 Days

- Improve scan rule precision for common LLM, RAG, agent, and MCP frameworks.
- Add more copy-paste scan examples for FastAPI, LangChain, LlamaIndex, notebooks, and CI.
- Add more sample policies for healthcare, finance, legal, HR, and customer support use cases.
- Expand documentation around `policyaware about`, `policyaware feedback`, and report footer feedback links.
- Collect real user feedback through:
  - GitHub Discussions: https://github.com/ktirupati/policyaware/discussions
  - Show and Tell: https://github.com/ktirupati/policyaware/discussions/categories/show-and-tell
  - Feedback form: https://docs.google.com/forms/d/e/1FAIpQLSc2QcQydjXZ0YF9bbVSpudoM5y8noxIP5jU-acVmjlyvf6Slg/viewform

## Next 60 Days

- Add more local code scan categories for AI framework misuse and governance drift.
- Improve scan baselining and suppression workflows for pull requests.
- Add richer examples for provider routing and approval workflows.
- Add policy bundle examples for regulated RAG, support copilots, code assistants, analytics agents, and multi-agent workflows.
- Improve OpenTelemetry and Prometheus documentation with production-style examples.
- Add more golden dataset examples for policy and RAG quality regression tests.

## Next 90 Days

- Explore a lightweight local report viewer or dashboard for scan and audit outputs.
- Add more enterprise integration examples for identity, approval, storage, and observability systems.
- Add optional deeper ML-assisted classifiers while keeping the default package rules-based, deterministic, and lightweight.
- Expand MCP/tool governance examples as tool protocols mature.
- Publish community case studies and permissioned testimonials.

## Known Limitations

- Real provider adapters require credentials and endpoints for live testing.
- Optional ML and guardrails integrations depend on third-party packages and their licenses.
- The local code scanner is a fast governance scanner, not a replacement for SAST, secret scanners, formal compliance review, or penetration testing.
- PolicyAware helps detect and govern risks; it does not guarantee compliance.

## Good Areas For Contributors

- New scan rules for AI frameworks.
- More examples and sample YAML policies.
- Provider-specific documentation improvements.
- CI/CD templates.
- RAG evaluation examples.
- MCP/tool governance examples.
- Report usability improvements.
- Tests for edge cases and regression coverage.

See [GOOD_FIRST_ISSUES.md](GOOD_FIRST_ISSUES.md) for starter tasks.
