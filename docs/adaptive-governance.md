# Adaptive Governance

PolicyAware includes lightweight adaptive governance features that go beyond simple allow/deny checks while staying deterministic, auditable, and safe for enterprise adoption.

These features are intentionally local and rules-based in the base package. They do not call external models, install heavy ML dependencies, or execute project code.

## What This Adds

| Feature | Purpose | Primary API / CLI |
| --- | --- | --- |
| Policy suggestion | Generate a conservative starter YAML policy from repository scan findings | `PolicySuggester`, `policyaware policy suggest` |
| Synthetic redaction | Replace sensitive values with structurally useful fake values instead of `[REDACTED]` | `DataProtectionEngine.synthesize`, `policyaware protect synthesize` |
| Safe rewrite | Return an auditable state patch that nudges risky agent flows to read-only, approval-first execution | `safe_rewrite` policy action, `state_mutation` |
| Plan preflight | Check a proposed multi-step agent plan before the first real tool call | `PlanPreflightChecker`, `policyaware plan check` |
| Shadow AI scan signals | Detect dynamic installs, subprocess execution, dynamic imports, and runtime tool registration | `policyaware scan` |

## 1. Generate A Policy From A Repository

Run a local scan and produce a suggested deny-by-default policy:

```bash
policyaware policy suggest . --out policyaware.generated.yaml --profile baseline
policyaware policy validate policyaware.generated.yaml
```

Profiles:

```bash
policyaware policy suggest . --profile baseline
policyaware policy suggest . --profile soc2
policyaware policy suggest . --profile hipaa
policyaware policy suggest . --profile gdpr
```

Python:

```python
from pathlib import Path
from policyaware import PolicySuggester

suggestion = PolicySuggester().suggest(Path("."))

print(suggestion.to_yaml())
print(suggestion.rationale)
print(suggestion.source_report.category_counts)
```

The generated policy is a starting point, not a legal compliance guarantee. Review it with your security, platform, and compliance teams before production use.

## 2. Use Synthetic Redaction

Placeholder redaction is safe but can reduce LLM quality:

```text
Email [REDACTED_EMAIL] or call [REDACTED_PHONE].
```

Synthetic redaction preserves useful structure:

```python
from policyaware import DataProtectionEngine

engine = DataProtectionEngine()
result = engine.synthesize(
    "Email krishna@example.com or call 212-555-7890 with card 4111 1111 1111 2222."
)

print(result.synthetic_text)
print(result.synthetic_map)
```

Example output:

```text
Email alex.morgan@example.com or call 415-555-0188 with card 4111 1111 1111 1111.
```

CLI:

```bash
policyaware protect synthesize "Email jane@example.com or call 212-555-7890"
policyaware protect synthesize "Email jane@example.com" --json
```

The reversible map should remain inside your trusted application boundary. Do not send the map to external model providers.

## 3. Return Safe Rewrite Decisions

PolicyAware can return an auditable trajectory correction instead of only blocking a workflow.

YAML:

```yaml
id: adaptive_safe_rewrite
default: deny

rules:
  - name: safe_rewrite_risky_tool_trajectory
    effect: transform
    action: safe_rewrite
    when:
      request.action_type_in: ["delete", "deploy", "payment", "refund"]

  - name: allow_developers
    effect: allow
    when:
      user.role: developer
```

Python:

```python
from policyaware import GatewayRequest, PolicyEngine, DataFindings

engine = PolicyEngine.from_file("policyaware.yaml")

decision = engine.decide(
    GatewayRequest(
        tenant="acme",
        app="agent",
        user={"role": "developer"},
        context={"action_type": "delete"},
        messages=[{"role": "user", "content": "Delete stale production records."}],
    ),
    DataFindings(),
)

print(decision.decision)
print(decision.actions)
print(decision.state_mutation)
```

The `state_mutation` payload contains rewritten messages and instructions that tell the agent to continue with read-only, least-privilege behavior until approval is granted.

## 4. Check A Multi-Step Agent Plan Before Execution

Create a plan:

```yaml
steps:
  - tool: database
    action: delete customer records
  - tool: deploy
    action: deploy production patch
  - tool: webhook
    action: send result to external url
```

Run preflight:

```bash
policyaware plan check plan.yaml
policyaware plan check plan.yaml --json
policyaware plan check plan.yaml --fail-on high
```

Python:

```python
from pathlib import Path
from policyaware import PlanPreflightChecker

report = PlanPreflightChecker().check_file(Path("plan.yaml"))

print(report.allowed)
print(report.highest_severity)
for finding in report.findings:
    print(finding.title, finding.recommendation)
```

Plan preflight is deterministic. It does not execute the plan. Use it before LangGraph, CrewAI, AutoGen, MCP, or custom multi-agent workflows execute real tool calls.

## 5. Detect Shadow AI Patterns In Code

`policyaware scan` flags high-signal patterns such as:

- runtime `pip install`, `npm install`, `poetry add`, or `yarn add`
- `subprocess.run`, `os.system`, shell pipes, `exec`, `eval`
- dynamic imports through `importlib.import_module` or `__import__`
- runtime tool registration outside PolicyAware governance

Run:

```bash
policyaware scan . --ruleset ai-agent-security --format html,json,sarif,markdown
```

The HTML report groups these under **Shadow AI Governance** and recommends allowlists, sandboxing, approval, and audit controls.

## Suggested Workflow

```bash
policyaware scan . --format html,json,sarif,markdown --fail-on high
policyaware policy suggest . --out policyaware.generated.yaml
policyaware policy validate policyaware.generated.yaml
policyaware plan check agent-plan.yaml --fail-on high
```

This gives teams an adoption path:

1. Scan repository governance gaps.
2. Generate a starter policy.
3. Validate the policy.
4. Preflight risky multi-step plans.
5. Use synthetic redaction or safe rewrite where user experience matters.

## Boundaries

Adaptive governance does not replace:

- sandboxing or container isolation
- identity and access management
- network egress controls
- secret management
- human approval systems
- formal legal/compliance review

Use it as a practical governance layer that makes policy decisions more helpful, auditable, and developer-friendly.
