# Production Checklist

Use this checklist before deploying PolicyAware into a production LLM, RAG, MCP, or agent workflow.

## 1. Scope The AI Workflow

- Identify every model call, RAG retrieval step, MCP/tool action, provider route, and approval path.
- Choose the PolicyAware entry point: `Gateway`, callback, `ToolPolicyEngine`, `MCPPolicyProxy`, sidecar, or `policyaware scan`.
- Keep PolicyAware focused on AI governance paths rather than ordinary non-AI APIs.

## 2. Keep The Install Lightweight

Start with:

```bash
pip install policyaware
```

Install extras only when needed:

```bash
pip install "policyaware[privacy]"
pip install "policyaware[ml]"
pip install "policyaware[guardrails]"
```

Do not use `policyaware[all]` in production containers unless the service truly needs every optional stack.

## 3. Validate Policies Before Runtime

```bash
policyaware policy validate policyaware.yaml
policyaware policy compose-check policy-stack.yaml
policyaware contract check ./src --policy tool-governance.yaml
```

Use deny-by-default policies and confirm explicit deny rules win over local allow overlays.

## 4. Add CI Scanning

```bash
policyaware scan . --format html,json,sarif,markdown --fail-on high
```

For GitHub Actions:

```yaml
- uses: actions/checkout@v4
- uses: ktirupati/policyaware-action@v1
```

Archive the HTML, JSON, SARIF, or Markdown report as release evidence.

## 5. Govern MCP And Tools

- Map every connector and action in YAML.
- Deny destructive actions by default.
- Require approval for write, delete, deploy, payment, permission, and data-export actions.
- Use `MCPPolicyProxy` for raw JSON-RPC `tools/call` traffic where MCP servers expose filesystem, Git, database, or enterprise API access.

Smoke test:

```bash
python examples/mcp-policy-proxy-demo/mcp_proxy_demo.py
```

## 6. Protect Sensitive Data

- Run `DataProtectionEngine.inspect(...)` or gateway preflight before sending prompts to external providers.
- Use `redact` transforms for roles that do not need raw PII.
- Add `policyaware[privacy]` only when stronger Presidio/spaCy entity detection is required.
- Keep reversible synthetic-redaction maps inside the trusted boundary.

## 7. Configure Audit And Observability

- Store audit traces in a durable location appropriate for your environment.
- Export metrics to existing dashboards through Prometheus/OpenTelemetry patterns.
- Preserve reason codes, matched rules, trace IDs, request IDs, and connector/action fields for blocked actions.

Useful commands:

```bash
policyaware audit view --traces-file .policyaware/traces.jsonl --out .policyaware/trace-viewer.html
policyaware observability prometheus
policyaware observability otel-json
```

## 8. Test Fail-Closed Behavior

Confirm the application blocks or requires approval when:

- policy YAML is invalid
- remote policy source is unavailable
- checksum validation fails
- optional validator times out
- required approval integration is unavailable
- tool action has no matching allow rule

## 9. Benchmark The Request Path

Run local benchmarks:

```bash
python benchmarks/benchmark_policy_engine.py --requests 1000 --concurrency 1
python benchmarks/benchmark_policy_engine.py --requests 1000 --concurrency 20
python benchmarks/benchmark_scan.py . --iterations 3
```

Record your own median, p95, p99, and requests-per-second results. Optional ML and guardrail extras can add significant overhead.

## 10. Review Security Boundaries

PolicyAware can govern actions before execution, but it does not replace:

- authentication and authorization
- network segmentation
- sandboxed tool execution
- secrets management
- container hardening
- dependency scanning
- legal/compliance review

For high-risk tools, combine PolicyAware decisions with Docker, Wasm, gVisor, Firecracker, Kubernetes job isolation, or another execution boundary.

## Release Evidence To Keep

- Policy YAML files and schema validation output.
- Scan reports and SARIF artifacts.
- Benchmark output.
- Audit trace samples.
- Approval workflow test output.
- MCP/tool governance test output.
- GitHub Actions run links.

