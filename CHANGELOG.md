# Changelog

All notable PolicyAware changes are tracked here.

## Unreleased

- No unreleased changes yet.

## 0.4.1

- Added CLI-native scan rulesets through `policyaware scan --ruleset`, keeping
  scanner categories and presets in the PolicyAware package as the single
  source of truth for local and CI integrations.
- Added hierarchical policy composition for global, compliance, region, tenant,
  app, and local policy layers with deny-wins conflict handling.
- Added runtime telemetry and sidecar `/metrics` for Prometheus-compatible
  policy, tool, approval, latency, and routing metrics.
- Added cold-start fallback policy support for dynamic policy sources so remote
  source outages resolve as remote source -> last known-good cache -> local
  emergency fallback -> fail closed.
- Hardened dynamic policy refresh with lock-protected atomic swaps so in-flight
  requests do not mix old and new policy engine state.
- Added structured blocked-action rejection payloads for prompt and tool
  decisions, plus telemetry attributes that preserve deny/approval reason codes,
  matched rules, trace IDs, and connector/action context.
- Added remote policy timeout and retry-storm protection with exponential
  backoff, jitter, and SDK timeout propagation for HTTP, S3, GCS, and ADLS
  dynamic policy sources.
- Hardened checksum-pinned remote policy refreshes so checksum mismatches log a
  critical alert, reject the downloaded policy, avoid poisoning the cache, and
  fall back to the last known-good cache when available.

## 0.4.0

- Added policy rollout/shadow evaluation, canary enforcement, parent trace/session correlation, and a static governance dashboard.
- Added enterprise hardening primitives: SQLite-backed session state, emergency revoke lists, policy checksum pinning, and optional signed audit traces.
- Added stateful session governance for cumulative sensitive-data leakage and repeated MCP/tool activity across conversations or agent runs.
- Added dynamic policy distribution from local, HTTP(S), AWS S3, Google Cloud Storage, or ADLS Gen2 sources with TTL refresh, last known-good cache support, fail-closed behavior, and `policyaware policy pull`.
- Added sidecar bearer-token enforcement and security-boundary documentation for out-of-process enterprise deployments.
- Added bundled policy packs for healthcare/HIPAA, finance, EU AI Act high-risk, and SOC 2 AI controls.
- Added `policyaware policy packs list/show/copy` so users can start from policy templates instead of blank YAML.
- Added lightweight dependency-free HTTP sidecar mode with `/health`, `/v1/check`, `/v1/tool/check`, `/v1/route`, and `/v1/evaluate`.
- Added observability templates for Grafana, Prometheus, and OpenTelemetry collector workflows.
- Added policy contract checks to detect drift between tool-governance YAML and Python tool signatures.

## 0.3.1

- Added optional Haystack-style integration components for RAG query governance, output evaluation, and agent tool permission checks.
- Added Haystack RAG governance example, documentation, optional install extra, and tests.
- Added Microsoft AGT-style interop helpers, evidence export docs, example, and tests.
- Added dependency-free LangGraph node guard, integration discovery CLI, enterprise control-plane demo, integration strategy docs, and lightweight benchmark guidance.
- Added explainable local integration recommender that scans project signals plus user hints and recommends the best PolicyAware entry point.
- Added `policyaware doctor`, `policyaware examples list/run`, recommendation HTML reports, and conservative policy migration helper.
- Added clearer maturity, optional dependency, latency, and category-fit guidance so users understand when to use PolicyAware versus guardrails, gateways, or model routers.

## 0.3.0

- Added user-friendly optional dependency aliases: `privacy`, `guardrails`, and `all`.
- Documented the lightweight default install and optional install profiles while keeping backward-compatible extras.
- Enhanced `policyaware scan` terminal output with a Rich dashboard for Critical, Warning, Passed, recommendations, and report paths.
- Added `policyaware init` to generate a NIST-aligned deny-by-default starter `policyaware.yaml`.
- Added lightweight LangChain and LlamaIndex callback handlers for streamed-token aggregation, policy review, risk scoring, output leakage checks, runtime evals, and token accounting.
- Sharpened project positioning around PolicyAware as an AI Gateway and Agent Control Plane while keeping implementation claims precise.
- Added architecture diagram, usage-mode guidance, enterprise-readiness checklist, and limitations/production-validation documentation.
- Added scan report preview assets, examples matrix, security model, and compatibility/integration status documentation.

## 0.2.9

- Added project-wide feedback and testimonial links for GitHub Discussions, Google Form feedback, and Show and Tell user stories.
- Added `policyaware about` and `policyaware feedback` CLI commands for pip-only users.
- Added feedback/testimonial links to scan HTML and Markdown reports, README, docs, and package metadata.
- Added adoption and testimonial tracking documents for open-source user insight collection.

## 0.2.8

- Added optional NeMo Guardrails and Guardrails AI adapter orchestration for full-stack guardrail workflows.
- Added stable `GuardrailResult` adapter contract and Gateway input/output guard hooks.
- Added full-stack guardrails example and documentation.

## 0.2.7

- Added local AI governance code scanning documentation and examples for HTML, JSON, SARIF, and Markdown reports.
- Added scan config YAML examples, inline suppressions, Git diff scanning, notebook/IaC coverage, CI templates, compliance filters, and remediation checklist documentation.

## 0.2.6

- Added SEO-focused GitHub Pages landing pages for FastAPI middleware, LangChain guardrails, MCP tool governance, PII redaction, and PolicyAware alternatives.
- Added sitemap, robots.txt, social preview image, canonical metadata, Open Graph metadata, and JSON-LD author metadata.
- Added captured demo-output documentation for runnable examples.
- Added provider credential quick reference and Search Console/Bing submission guidance.
- Added changelog link to package metadata and README.
- Updated docs and wiki links for published Dev.to and Medium articles.

## 0.2.5

- Added author metadata for Krishna Kishor Tirupati.
- Added production provider adapter classes for OpenAI-compatible APIs, Azure OpenAI, Anthropic, Bedrock, Vertex AI, Ollama, and vLLM.
- Added optional ML signal integrations for Presidio PII detection, ProtectAI prompt-injection detection, and Transformers-based domain/risk classification.
- Added policy schema validation.
- Added persistent SQLite audit storage, trace viewer output, Prometheus text export, and OpenTelemetry-shaped JSON export.
- Added approval hooks and executable golden dataset evaluation examples.
- Expanded GitHub Pages, wiki, README, and user guide documentation.

## 0.2.4

- Added enterprise MVP examples for PII redaction, regulated RAG, MCP tool governance, provider routing, audit trace viewing, and approval workflow hooks.
- Added copy-paste example folders with captured terminal output.

## 0.2.0

- Added risk-tier classification, explainable reason codes, governance-aware evaluations, audit bundles, and MCP-style tool governance.

## 0.1.0

- Initial open-source scaffold with deny-by-default YAML policy engine, data protection checks, model routing abstraction, simulated provider, runtime evaluation hooks, audit traces, CLI, and framework integration shims.
