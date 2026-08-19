from __future__ import annotations

import json
import os
import subprocess
import sys
from importlib.util import find_spec
from pathlib import Path

import typer
import yaml
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from policyaware.audit import AuditBundleWriter, AuditLogger, SQLiteAuditLogger, TraceViewer
from policyaware.contracts import PolicyContractChecker
from policyaware.data_protection import DataProtectionEngine
from policyaware.dashboard import GovernanceDashboard
from policyaware.evals import EvalSuiteRunner
from policyaware.gateway import Gateway
from policyaware.integrations.recommender import IntegrationRecommender
from policyaware.models import GatewayRequest, ToolCallRequest
from policyaware.observability import OpenTelemetryJsonExporter, PrometheusExporter
from policyaware.policy import PolicyEngine
from policyaware.policy_composition import PolicyComposer, PolicyCompositionError, load_policy_layers
from policyaware.policy_pack_registry import copy_policy_pack, list_policy_packs, read_policy_pack
from policyaware.policy_schema import PolicySchemaValidator, PolicyValidationError
from policyaware.policy_source import policy_source_from_uri
from policyaware.risk import RiskClassifier
from policyaware.rollout import PolicyRollout
from policyaware.scanner import LocalCodeScanner, ScanConfig, git_changed_files
from policyaware.session_state import SessionStateMonitor, SQLiteSessionStateStore
from policyaware.sidecar import serve_sidecar
from policyaware.tools import ToolPolicyEngine

app = typer.Typer(help="PolicyAware AI Gateway CLI")
policy_app = typer.Typer(help="Policy testing commands")
policy_packs_app = typer.Typer(help="Policy pack commands")
eval_app = typer.Typer(help="Evaluation commands")
dev_app = typer.Typer(help="Local development commands")
tools_app = typer.Typer(help="MCP and tool governance commands")
audit_app = typer.Typer(help="Audit and replay commands")
risk_app = typer.Typer(help="Risk classification commands")
observability_app = typer.Typer(help="Metrics and trace export commands")
guards_app = typer.Typer(help="Guardrails integration commands")
integrations_app = typer.Typer(help="Integration discovery commands")
examples_app = typer.Typer(help="Runnable example commands")
contract_app = typer.Typer(help="Policy/code contract drift commands")
app.add_typer(policy_app, name="policy")
policy_app.add_typer(policy_packs_app, name="packs")
app.add_typer(eval_app, name="eval")
app.add_typer(dev_app, name="dev")
app.add_typer(tools_app, name="tools")
app.add_typer(audit_app, name="audit")
app.add_typer(risk_app, name="risk")
app.add_typer(observability_app, name="observability")
app.add_typer(guards_app, name="guards")
app.add_typer(integrations_app, name="integrations")
app.add_typer(examples_app, name="examples")
app.add_typer(contract_app, name="contract")
console = Console()

PROJECT_URL = "https://github.com/ktirupati/policyaware"
DOCS_URL = "https://ktirupati.github.io/policyaware/"
PYPI_URL = "https://pypi.org/project/policyaware/"
DISCUSSIONS_URL = "https://github.com/ktirupati/policyaware/discussions"
ISSUES_URL = "https://github.com/ktirupati/policyaware/issues"
TESTIMONIALS_URL = "https://github.com/ktirupati/policyaware/discussions/categories/show-and-tell"
FEEDBACK_FORM_URL = (
    "https://docs.google.com/forms/d/e/1FAIpQLSc2QcQydjXZ0YF9bbVSpudoM5y8noxIP5jU-acVmjlyvf6Slg/viewform"
)
LINKEDIN_URL = "https://www.linkedin.com/in/krishna-tirupati/"
INTEGRATIONS = [
    {
        "name": "FastAPI",
        "status": "shim/example",
        "extra": "base",
        "install": "pip install policyaware",
        "example": "examples/fastapi-llm-policy-middleware",
        "notes": "Protect API routes before LLM execution.",
    },
    {
        "name": "LangChain",
        "status": "available",
        "extra": "base",
        "install": "pip install policyaware",
        "example": "examples/langchain-policy-guardrails",
        "notes": "Callbacks and wrapper patterns for chain-style LLM calls.",
    },
    {
        "name": "LangGraph",
        "status": "available",
        "extra": "base",
        "install": "pip install policyaware",
        "example": "examples/langgraph-agent-governance",
        "notes": "Dependency-free node guard for state, tool calls, and approvals.",
    },
    {
        "name": "LlamaIndex",
        "status": "available",
        "extra": "base",
        "install": "pip install policyaware",
        "example": "docs/capabilities/integration-callbacks.md",
        "notes": "RAG-oriented callback checks for streamed output and citations.",
    },
    {
        "name": "Haystack",
        "status": "available",
        "extra": "haystack",
        "install": 'pip install "policyaware[haystack]"',
        "example": "examples/haystack-policyaware-rag-governance",
        "notes": "RAG query, output, and agent tool governance components.",
    },
    {
        "name": "Guardrails AI",
        "status": "optional adapter",
        "extra": "guardrails",
        "install": 'pip install "policyaware[guardrails]"',
        "example": "examples/full-stack-guardrails",
        "notes": "Optional validation engine orchestrated by PolicyAware.",
    },
    {
        "name": "NVIDIA NeMo Guardrails",
        "status": "optional adapter",
        "extra": "guardrails",
        "install": 'pip install "policyaware[guardrails]"',
        "example": "examples/full-stack-guardrails",
        "notes": "Optional conversational guardrail engine orchestrated by PolicyAware.",
    },
    {
        "name": "Microsoft AGT-style evidence",
        "status": "available",
        "extra": "base",
        "install": "pip install policyaware",
        "example": "examples/microsoft-agt-interop",
        "notes": "Dependency-free evidence JSON export, not an official Microsoft wire contract.",
    },
    {
        "name": "Provider adapters",
        "status": "available",
        "extra": "providers",
        "install": 'pip install "policyaware[providers]"',
        "example": "docs/provider-adapter-examples.md",
        "notes": "Azure OpenAI, Anthropic, Bedrock, Vertex AI, Ollama, vLLM, OpenAI-compatible.",
    },
    {
        "name": "Privacy ML",
        "status": "optional",
        "extra": "privacy",
        "install": 'pip install "policyaware[privacy]"',
        "example": "docs/ml-integrations.md",
        "notes": "Microsoft Presidio and spaCy for stronger privacy detection.",
    },
]
EXAMPLES = [
    {
        "id": "fastapi-llm-policy-middleware",
        "command": ["app.py"],
        "description": "Protect a FastAPI route before LLM execution.",
    },
    {
        "id": "langchain-policy-guardrails",
        "command": ["chain_demo.py"],
        "description": "Apply PolicyAware checks around LangChain-style calls.",
    },
    {
        "id": "langgraph-agent-governance",
        "command": ["langgraph_demo.py"],
        "description": "Guard graph state, nodes, and tool calls.",
    },
    {
        "id": "haystack-policyaware-rag-governance",
        "command": ["rag_pipeline_demo.py"],
        "description": "Govern Haystack-style RAG query and output flow.",
    },
    {
        "id": "mcp-tool-permission-gateway",
        "command": ["tool_gateway_demo.py"],
        "description": "Check MCP-style connector/action permissions.",
    },
    {
        "id": "microsoft-agt-interop",
        "command": ["agt_interop_demo.py"],
        "description": "Export tool decisions as AGT-style evidence JSON.",
    },
    {
        "id": "enterprise-ai-control-plane",
        "command": ["control_plane_demo.py"],
        "description": "Show prompt, routing, tool, eval, audit, and evidence flow together.",
    },
    {
        "id": "pii-redaction-policy",
        "command": ["pii_demo.py"],
        "description": "Detect and redact PII before model execution.",
    },
    {
        "id": "provider-routing-by-risk",
        "command": ["routing_demo.py"],
        "description": "Route by risk, region, policy, cost, and availability.",
    },
    {
        "id": "regulated-rag-assistant",
        "command": ["rag_demo.py"],
        "description": "Require citations and stronger controls for regulated RAG.",
    },
]
OPTIONAL_DEPENDENCY_GROUPS = {
    "privacy": ["presidio_analyzer", "presidio_anonymizer", "spacy"],
    "guardrails": ["nemoguardrails", "guardrails"],
    "haystack": ["haystack"],
    "providers": ["boto3"],
    "ml": ["transformers", "torch"],
    "onnx": ["optimum", "onnxruntime"],
}
PROVIDER_ENV_VARS = {
    "Azure OpenAI": ["AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY"],
    "Anthropic": ["ANTHROPIC_API_KEY"],
    "AWS Bedrock": ["AWS_ACCESS_KEY_ID", "AWS_REGION"],
    "Vertex AI": ["GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT"],
    "Ollama": ["OLLAMA_HOST"],
    "vLLM": ["VLLM_BASE_URL"],
}
BASELINE_POLICY_TEMPLATE = """# PolicyAware starter policy
# Generated by: policyaware init
#
# This template is NIST-aligned, not a formal compliance certification.
# Review and adapt it for your organization, tenant model, regions,
# approval workflows, providers, and risk tolerance before production use.

id: policyaware_baseline_policy
schema_version: "0.2"
default: deny

rules:
  # Data protection baseline
  - name: deny_secret_leakage
    effect: deny
    when:
      data.contains_secrets: true

  - name: redact_pii_for_standard_users
    effect: transform
    action: redact
    when:
      data.contains_pii: true
      user.role_not_in:
        - privacy_admin
        - compliance_officer

  - name: redact_phi_for_non_privileged_users
    effect: transform
    action: redact
    when:
      data.contains_phi: true
      user.role_not_in:
        - clinician
        - privacy_admin
        - compliance_officer

  # MCP/tool governance baseline. Applications should map tool requests
  # into request.action_type and request.tool_command before policy evaluation.
  - name: deny_risky_mcp_tool_commands
    effect: deny
    when:
      request.tool_command_in:
        - rm -rf
        - del /s
        - format
        - mkfs
        - dd
        - shutdown
        - reboot
        - chmod 777
        - chown -R
        - curl | sh
        - wget | sh
        - powershell -enc
        - Invoke-WebRequest
        - kubectl delete
        - terraform destroy

  - name: require_approval_for_side_effecting_tools
    effect: require_approval
    when:
      request.action_type_in:
        - write
        - delete
        - deploy
        - payment
        - refund
        - permission_change
        - external_send

  # Budget and loop controls for agentic workflows. Applications should
  # pass max_tokens and max_iterations in request context.
  - name: deny_excessive_token_budget
    effect: deny
    when:
      request.max_tokens_gte: 8193

  - name: require_approval_for_high_agent_iterations
    effect: require_approval
    when:
      request.max_iterations_gte: 11

  - name: require_approval_for_high_or_critical_risk
    effect: require_approval
    when:
      risk.tier_in:
        - high
        - critical

  # Explicit allow rules. Keep the policy deny-by-default and add only
  # the roles, regions, tenants, and task types your application supports.
  - name: allow_low_medium_risk_enterprise_users
    effect: allow
    when:
      user.role_in:
        - developer
        - analyst
        - support_agent
        - platform_engineer
        - privacy_admin
        - compliance_officer
      request.region_in:
        - us
        - eu
      risk.tier_in:
        - low
        - medium
"""


def _project_links_table(title: str) -> Table:
    table = Table(title=title)
    table.add_column("Resource")
    table.add_column("Link")
    table.add_row("Documentation", DOCS_URL)
    table.add_row("GitHub", PROJECT_URL)
    table.add_row("PyPI", PYPI_URL)
    table.add_row("Issues", ISSUES_URL)
    table.add_row("Discussions", DISCUSSIONS_URL)
    table.add_row("Feedback form", FEEDBACK_FORM_URL)
    table.add_row("Testimonials / Show and Tell", TESTIMONIALS_URL)
    table.add_row("Maintainer LinkedIn", LINKEDIN_URL)
    return table


def _render_policy_composition_report(report) -> None:
    table = Table(title="Policy Composition Report")
    table.add_column("Layer Order")
    table.add_column("Status")
    table.add_row(" -> ".join(report.layers), "errors" if report.has_errors else "ok")
    console.print(table)

    findings = Table(title="Hierarchy Findings")
    findings.add_column("Severity")
    findings.add_column("Code")
    findings.add_column("Layer")
    findings.add_column("Rule")
    findings.add_column("Message")
    if not report.findings:
        findings.add_row("info", "POLICY_COMPOSITION.OK", "-", "-", "No hierarchy conflicts detected.")
    for finding in report.findings:
        style = "red" if finding.severity == "error" else "yellow" if finding.severity == "warning" else "cyan"
        findings.add_row(
            f"[{style}]{finding.severity}[/{style}]",
            finding.code,
            finding.layer or "-",
            finding.rule or "-",
            finding.message,
        )
    console.print(findings)
    console.print(
        "Precedence: emergency > global > compliance > region > tenant > app > local_override. "
        "Explicit deny remains deny-first in the composed policy."
    )


def _examples_root() -> Path:
    repo_examples = Path.cwd() / "examples"
    if repo_examples.exists():
        return repo_examples
    return Path(__file__).resolve().parents[2] / "examples"


def _example_by_id(example_id: str) -> dict[str, object] | None:
    normalized = example_id.strip().lower()
    return next((item for item in EXAMPLES if item["id"] == normalized), None)


def _starter_policy_template(profile: str) -> str:
    normalized = profile.strip().lower()
    if normalized != "baseline":
        raise typer.BadParameter("Only the 'baseline' init profile is currently supported.")
    return BASELINE_POLICY_TEMPLATE


def _parse_size(value: str) -> int:
    normalized = value.strip().lower()
    multiplier = 1
    if normalized.endswith("kb"):
        multiplier = 1024
        normalized = normalized[:-2]
    elif normalized.endswith("mb"):
        multiplier = 1024 * 1024
        normalized = normalized[:-2]
    elif normalized.endswith("b"):
        normalized = normalized[:-1]
    try:
        return int(float(normalized) * multiplier)
    except ValueError as exc:
        raise typer.BadParameter("Use a size like 512kb, 1mb, or 1048576.") from exc


def _parse_csv(value: str | None) -> list[str] | None:
    if value is None:
        return None
    parsed = [item.strip() for item in value.split(",") if item.strip()]
    return parsed or None


def _should_fail_scan(fail_on: str, severity_counts: dict[str, int]) -> bool:
    normalized = fail_on.strip().lower()
    if normalized in {"", "none", "off", "never"}:
        return False
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    if normalized not in order:
        raise typer.BadParameter("Use one of: critical, high, medium, low, none.")
    threshold = order[normalized]
    return any(count and order[severity] <= threshold for severity, count in severity_counts.items())


def _contract_should_fail(fail_on: str, report) -> bool:
    normalized = fail_on.strip().lower()
    if normalized in {"", "none", "off", "never"}:
        return False
    severities = {finding.severity for finding in report.findings}
    if normalized == "critical":
        return "critical" in severities
    if normalized == "high":
        return bool(severities & {"critical", "high"})
    raise typer.BadParameter("Use one of: high, critical, none.")


def _load_ignore_patterns(path: Path | None) -> list[str]:
    if path is None or not path.exists():
        return []
    patterns: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def _load_baseline(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {str(item) for item in data}
    if isinstance(data, dict):
        if isinstance(data.get("fingerprints"), list):
            return {str(item) for item in data["fingerprints"]}
        if isinstance(data.get("findings"), list):
            return {
                str(item["fingerprint"])
                for item in data["findings"]
                if isinstance(item, dict) and item.get("fingerprint")
            }
    return set()


def _write_baseline(path: Path, fingerprints: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": "0.1",
                "tool": "policyaware",
                "fingerprints": sorted(set(fingerprints)),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _migrated_policy(policy: dict, target_version: str) -> dict:
    migrated = dict(policy)
    migrated["schema_version"] = target_version
    migrated.setdefault("default", "deny")
    migrated.setdefault("rules", [])
    return migrated


def _render_scan_dashboard(
    report,
    *,
    json_out: Path | None = None,
    sarif_out: Path | None = None,
    markdown_out: Path | None = None,
    write_baseline: Path | None = None,
    diff: bool = False,
    diff_files: list[str] | None = None,
) -> None:
    summary = Table.grid(expand=True)
    summary.add_column(justify="center")
    summary.add_column(justify="center")
    summary.add_column(justify="center")
    summary.add_column(justify="center")
    summary.add_column(justify="center")
    summary.add_row(
        f"[bold]{report.overall_risk}[/bold]\n[dim]Overall risk[/dim]",
        f"[bold]{report.files_scanned}[/bold]\n[dim]Files scanned[/dim]",
        f"[bold]{len(report.findings)}[/bold]\n[dim]Findings[/dim]",
        f"[bold]{report.duration_seconds:.2f}s[/bold]\n[dim]Scan time[/dim]",
        f"[bold]{report.policy_coverage_score}%[/bold]\n[dim]Policy coverage[/dim]",
    )
    console.print(
        Panel(
            summary,
            title="[bold]PolicyAware Local Code Scan[/bold]",
            subtitle="AI governance scanner",
            border_style=_risk_style(report.overall_risk),
        )
    )

    console.print(
        Panel(
            _finding_status_table(
                "Critical",
                [finding for finding in report.findings if finding.severity in {"critical", "high"}],
                "red",
            ),
            border_style="red",
        )
    )
    console.print(
        Panel(
            _finding_status_table(
                "Warning",
                [finding for finding in report.findings if finding.severity in {"medium", "low"}],
                "yellow",
            ),
            border_style="yellow",
        )
    )
    console.print(
        Panel(
            _passed_checks_table(report),
            border_style="green",
        )
    )

    recommendations = Table(title="Top Recommendations", box=box.SIMPLE_HEAVY)
    recommendations.add_column("Priority", style="bold cyan", no_wrap=True)
    recommendations.add_column("Recommendation")
    for index, item in enumerate(_scan_recommendations(report), start=1):
        recommendations.add_row(str(index), item)
    console.print(recommendations)

    outputs = Table(title="Reports", box=box.SIMPLE_HEAVY)
    outputs.add_column("Format", style="bold")
    outputs.add_column("Path")
    outputs.add_row("HTML", report.output_path)
    if json_out:
        outputs.add_row("JSON", str(json_out.resolve()))
    if sarif_out:
        outputs.add_row("SARIF", str(sarif_out.resolve()))
    if markdown_out:
        outputs.add_row("Markdown", str(markdown_out.resolve()))
    if write_baseline:
        outputs.add_row("Baseline", str(write_baseline.resolve()))
    outputs.add_row("Suppressed", str(report.suppressed_findings))
    outputs.add_row("Baseline ignored", str(report.baseline_ignored))
    if diff:
        outputs.add_row("Diff files matched", str(len(diff_files or [])))
    console.print(outputs)


def _risk_style(overall_risk: str) -> str:
    return {
        "Critical": "red",
        "High": "red",
        "Medium": "yellow",
        "Low": "blue",
        "Clean": "green",
    }.get(overall_risk, "cyan")


def _finding_status_table(title: str, findings: list, style: str) -> Table:
    table = Table(title=f"[{style}]{title}[/{style}]", box=box.SIMPLE, show_lines=False)
    table.add_column("Status", no_wrap=True)
    table.add_column("Finding")
    if not findings:
        table.add_row(f"[{style}]None[/{style}]", "No findings in this group.")
        return table
    for finding in findings[:8]:
        table.add_row(
            f"[{style}]{finding.severity.upper()}[/{style}]",
            f"{finding.file}:{finding.line} - {finding.title}",
        )
    if len(findings) > 8:
        table.add_row(f"[{style}]+{len(findings) - 8}[/{style}]", "More findings in the report.")
    return table


def _passed_checks_table(report) -> Table:
    table = Table(title="[green]Passed[/green]", box=box.SIMPLE, show_lines=False)
    table.add_column("Status", style="green", no_wrap=True)
    table.add_column("Check")
    for item in _passed_scan_checks(report):
        table.add_row("PASS", item)
    return table


def _passed_scan_checks(report) -> list[str]:
    categories = report.category_counts
    checks: list[str] = []
    if not categories["Secrets"]:
        checks.append("No hardcoded secrets detected")
    if not categories["PHI"]:
        checks.append("No PHI detected")
    if not categories["PII"]:
        checks.append("No plain-text PII detected")
    if not categories["Tool Governance"] and not categories["Agent Tool Governance"]:
        checks.append("No ungoverned MCP/tool definitions detected")
    if not categories["Cost Governance"]:
        checks.append("No missing budget/rate/timeout controls detected")
    if not categories["LLM Governance"]:
        checks.append("No direct LLM calls bypassing PolicyAware detected")
    if not categories["Policy YAML"]:
        checks.append("No policy YAML quality issues detected")
    if not categories["Auditability"]:
        checks.append("No audit trace gaps detected")
    if not checks:
        checks.append("Review report for remediation before marking checks passed")
    return checks[:8]


def _scan_recommendations(report) -> list[str]:
    recommendations: list[str] = []
    categories = report.category_counts
    if categories["Secrets"]:
        recommendations.append("Rotate exposed credentials and move secrets to a secret manager.")
    if categories["PII"] or categories["PHI"]:
        recommendations.append("Redact sensitive data before prompts reach models, tools, logs, or reports.")
    if categories["Tool Governance"] or categories["Agent Tool Governance"]:
        recommendations.append("Add connector/action permissions and approval checks for MCP or agent tools.")
    if categories["Cost Governance"]:
        recommendations.append("Add token budgets, rate limits, timeouts, and retry controls around model calls.")
    if categories["LLM Governance"] or categories["Provider Governance"]:
        recommendations.append("Route provider calls through PolicyAware Gateway for policy, risk, routing, and audit.")
    if categories["RAG Governance"]:
        recommendations.append("Add source metadata, grounding, and citation checks for RAG outputs.")
    if report.policy_coverage_missing:
        recommendations.append(
            "Improve policy coverage for: " + ", ".join(report.policy_coverage_missing[:5]) + "."
        )
    if not recommendations:
        recommendations.append("No high-signal findings detected. Keep scanning in local development and CI.")
    return recommendations[:6]


@app.command("about")
def about() -> None:
    """Show project, documentation, and maintainer links."""
    console.print("[bold]PolicyAware AI Gateway[/bold]")
    console.print(
        "Open-source policy-aware control plane for governed LLM, RAG, MCP/tool, "
        "and AI-agent applications."
    )
    console.print("Created and maintained by Krishna Kishor Tirupati.")
    console.print(f"Docs: {DOCS_URL}")
    console.print(f"GitHub: {PROJECT_URL}")
    console.print(f"Feedback: {DISCUSSIONS_URL}")
    console.print(_project_links_table("PolicyAware Links"))


@app.command("feedback")
def feedback() -> None:
    """Show feedback, issue, and testimonial links."""
    console.print("[bold]PolicyAware Feedback And Testimonials[/bold]")
    console.print(
        "Share real-world usage, feature requests, issues, testimonials, and Show and Tell stories."
    )
    console.print("Please do not share secrets, private prompts, PHI, PII, or confidential data.")
    console.print(f"Feedback form: {FEEDBACK_FORM_URL}")
    console.print(f"GitHub Discussions: {DISCUSSIONS_URL}")
    console.print(f"Testimonials / Show and Tell: {TESTIMONIALS_URL}")
    console.print(_project_links_table("Feedback Channels"))


@app.command("doctor")
def doctor(
    policy_file: Path | None = typer.Option(
        None,
        "--policy",
        help="Optional PolicyAware YAML policy file to validate.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Print health report as JSON."),
) -> None:
    """Check local PolicyAware install health and optional integration readiness."""
    checks: list[dict[str, object]] = []
    checks.append(
        {
            "name": "Python version",
            "status": sys.version_info >= (3, 10),
            "detail": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        }
    )
    for package in ("pydantic", "yaml", "typer", "rich"):
        checks.append(
            {
                "name": f"Base dependency: {package}",
                "status": find_spec(package) is not None,
                "detail": "installed" if find_spec(package) is not None else "missing",
            }
        )
    for group, packages in OPTIONAL_DEPENDENCY_GROUPS.items():
        installed = [package for package in packages if find_spec(package) is not None]
        checks.append(
            {
                "name": f"Optional extra: {group}",
                "status": bool(installed),
                "detail": f"{len(installed)}/{len(packages)} packages detected",
            }
        )
    for provider, env_vars in PROVIDER_ENV_VARS.items():
        present = [name for name in env_vars if os.environ.get(name)]
        checks.append(
            {
                "name": f"Provider env: {provider}",
                "status": bool(present),
                "detail": f"{len(present)}/{len(env_vars)} env vars present; values hidden",
            }
        )
    if policy_file:
        try:
            policy = yaml.safe_load(policy_file.read_text(encoding="utf-8")) or {}
            PolicySchemaValidator().validate(policy)
            policy_status = True
            policy_detail = "valid"
        except Exception as exc:  # noqa: BLE001 - CLI health command reports all validation failures.
            policy_status = False
            policy_detail = str(exc)
        checks.append({"name": f"Policy file: {policy_file}", "status": policy_status, "detail": policy_detail})
    report = {
        "ok": all(
            bool(item["status"])
            for item in checks
            if not str(item["name"]).startswith(("Optional extra", "Provider env"))
        ),
        "checks": checks,
    }
    if json_output:
        console.print_json(data=report)
        return
    table = Table(title="PolicyAware Doctor")
    table.add_column("Status")
    table.add_column("Check")
    table.add_column("Detail")
    for item in checks:
        status = "[green]PASS[/green]" if item["status"] else "[yellow]INFO[/yellow]"
        if policy_file and str(item["name"]).startswith("Policy file") and not item["status"]:
            status = "[red]FAIL[/red]"
        table.add_row(status, str(item["name"]), str(item["detail"]))
    console.print(table)
    console.print("[dim]Provider checks only verify env var presence and never print secret values.[/dim]")


@app.command("init")
def init_policy(
    out: Path = typer.Option(
        Path("policyaware.yaml"),
        "--out",
        "-o",
        help="Output path for the generated starter policy.",
    ),
    profile: str = typer.Option(
        "baseline",
        "--profile",
        help="Starter policy profile to generate. Currently supports: baseline.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite the output file if it already exists.",
    ),
) -> None:
    """Generate a NIST-aligned baseline starter policy YAML."""
    if out.exists() and not force:
        console.print(
            f"[bold red]Refusing to overwrite existing file:[/bold red] {out}\n"
            "Use --force to replace it, or --out to choose another path."
        )
        raise typer.Exit(code=1)
    out.parent.mkdir(parents=True, exist_ok=True)
    template = _starter_policy_template(profile)
    out.write_text(template, encoding="utf-8")
    console.print(f"[bold green]Created PolicyAware starter policy:[/bold green] {out.resolve()}")
    console.print("Next steps:")
    console.print(f"  policyaware policy validate {out}")
    console.print(f"  policyaware policy explain {out} --prompt \"Email jane@example.com\"")


@app.command("up")
def up(
    policy_file: Path | None = typer.Option(None, "--policy", "--config", help="PolicyAware YAML policy file."),
    policy_url: str | None = typer.Option(
        None,
        "--policy-url",
        help="Central policy source URI: HTTP(S), s3://, gs://, abfs://, or abfss://.",
    ),
    tool_policy_file: Path | None = typer.Option(
        None,
        "--tool-policy",
        help="Optional MCP/tool governance YAML file.",
    ),
    host: str = typer.Option("127.0.0.1", "--host", help="Host interface for the sidecar."),
    port: int = typer.Option(8080, "--port", help="Port for the sidecar."),
    auth_token: str | None = typer.Option(
        None,
        "--auth-token",
        help="Optional bearer token required by POST endpoints. Prefer --auth-env in production.",
    ),
    auth_env: str = typer.Option(
        "POLICYAWARE_SIDECAR_TOKEN",
        "--auth-env",
        help="Environment variable used for the sidecar bearer token.",
    ),
    require_auth: bool = typer.Option(
        False,
        "--require-auth",
        help="Fail startup unless --auth-token or --auth-env provides a token.",
    ),
    policy_auth_token: str | None = typer.Option(
        None,
        "--policy-auth-token",
        help="Optional bearer token used when fetching --policy-url.",
    ),
    policy_auth_env: str = typer.Option(
        "POLICYAWARE_POLICY_TOKEN",
        "--policy-auth-env",
        help="Environment variable used for --policy-url bearer auth.",
    ),
    policy_cache: Path | None = typer.Option(
        Path(".policyaware/policy-cache.yaml"),
        "--policy-cache",
        help="Last known-good policy cache for dynamic policy URLs.",
    ),
    policy_refresh_seconds: float = typer.Option(
        60.0,
        "--policy-refresh-seconds",
        help="Refresh interval for dynamic policy sources.",
    ),
    policy_timeout_seconds: float = typer.Option(
        5.0,
        "--policy-timeout-seconds",
        help="Strict timeout for HTTP/S3/GCS/ADLS policy fetches.",
    ),
    policy_retry_base_seconds: float = typer.Option(
        1.0,
        "--policy-retry-base-seconds",
        help="Initial exponential backoff delay after a failed dynamic policy refresh.",
    ),
    policy_retry_max_seconds: float = typer.Option(
        60.0,
        "--policy-retry-max-seconds",
        help="Maximum exponential backoff delay after repeated dynamic policy refresh failures.",
    ),
    policy_retry_jitter_seconds: float = typer.Option(
        0.25,
        "--policy-retry-jitter-seconds",
        help="Random jitter added to dynamic policy retry delays to reduce retry storms.",
    ),
    fail_open: bool = typer.Option(
        False,
        "--fail-open",
        help="Continue using the last loaded policy if dynamic refresh fails.",
    ),
    session_state: bool = typer.Option(
        False,
        "--session-state",
        help="Enable stateful session inspection for cumulative leakage and repeated tool calls.",
    ),
    max_session_sensitive_findings: int = typer.Option(
        10,
        "--max-session-sensitive-findings",
        help="Deny when cumulative sensitive findings in a session exceed this value.",
    ),
    max_session_tool_calls: int = typer.Option(
        25,
        "--max-session-tool-calls",
        help="Deny when tool calls in a session exceed this value.",
    ),
    max_same_tool_action: int = typer.Option(
        10,
        "--max-same-tool-action",
        help="Deny when the same connector/action repeats above this value in a session.",
    ),
    session_state_store: str = typer.Option(
        "memory",
        "--session-state-store",
        help="Session state backend: memory or sqlite.",
    ),
    session_state_db: Path = typer.Option(
        Path(".policyaware/session-state.db"),
        "--session-state-db",
        help="SQLite session-state database path when --session-state-store sqlite is used.",
    ),
    revoke_file: Path | None = typer.Option(
        None,
        "--revoke-file",
        help="Emergency revoke YAML evaluated before normal policy/tool decisions.",
    ),
    policy_sha256: str | None = typer.Option(
        None,
        "--policy-sha256",
        help="Expected SHA256 checksum for the dynamically loaded policy source.",
    ),
    fallback_policy: Path | None = typer.Option(
        None,
        "--fallback-policy",
        help="Restrictive local fallback policy used when --policy-url and cache are unavailable.",
    ),
    audit_signing_secret: str | None = typer.Option(
        None,
        "--audit-signing-secret",
        help="Optional HMAC secret used to sign JSONL audit trace payloads.",
    ),
    audit_signing_env: str = typer.Option(
        "POLICYAWARE_AUDIT_SIGNING_SECRET",
        "--audit-signing-env",
        help="Environment variable used for audit trace signing.",
    ),
    rollout_policy: Path | None = typer.Option(
        None,
        "--rollout-policy",
        help="Candidate policy YAML for shadow or canary rollout.",
    ),
    rollout_mode: str = typer.Option(
        "shadow",
        "--rollout-mode",
        help="Rollout mode: shadow or enforce.",
    ),
    rollout_percentage: int = typer.Option(
        100,
        "--rollout-percentage",
        help="Percentage of traffic selected for candidate policy evaluation.",
    ),
) -> None:
    """Run a lightweight HTTP sidecar for non-Python services."""
    policy_source = policy_url or policy_file
    if policy_source is None:
        raise typer.BadParameter("Provide --policy or --policy-url.")
    if policy_url is None and policy_file and not policy_file.exists():
        raise typer.BadParameter(f"Policy file does not exist: {policy_file}")
    if tool_policy_file and not tool_policy_file.exists():
        raise typer.BadParameter(f"Tool policy file does not exist: {tool_policy_file}")
    resolved_auth_token = auth_token or os.getenv(auth_env)
    resolved_policy_auth_token = policy_auth_token or os.getenv(policy_auth_env)
    resolved_audit_signing_secret = audit_signing_secret or os.getenv(audit_signing_env)
    if require_auth and not resolved_auth_token:
        raise typer.BadParameter(
            f"Sidecar auth is required but no token was provided. Set {auth_env} or pass --auth-token."
        )
    if policy_timeout_seconds <= 0:
        raise typer.BadParameter("--policy-timeout-seconds must be greater than zero.")
    if policy_retry_base_seconds < 0 or policy_retry_max_seconds < 0 or policy_retry_jitter_seconds < 0:
        raise typer.BadParameter("Policy retry backoff values must be zero or greater.")
    if policy_retry_max_seconds and policy_retry_base_seconds > policy_retry_max_seconds:
        raise typer.BadParameter("--policy-retry-base-seconds cannot exceed --policy-retry-max-seconds.")
    console.print(f"[bold green]Starting PolicyAware sidecar[/bold green] http://{host}:{port}")
    console.print(f"Auth: {'enabled' if resolved_auth_token else 'disabled'}")
    if policy_url:
        console.print(
            f"Dynamic policy: enabled, refresh={policy_refresh_seconds}s, "
            f"timeout={policy_timeout_seconds}s, cache={policy_cache}, fail_closed={not fail_open}"
        )
    monitor = (
        SessionStateMonitor(
            max_sensitive_findings_per_session=max_session_sensitive_findings,
            max_tool_calls_per_session=max_session_tool_calls,
            max_same_tool_action_per_session=max_same_tool_action,
            store=SQLiteSessionStateStore(session_state_db)
            if session_state_store == "sqlite"
            else None,
        )
        if session_state
        else None
    )
    if session_state_store not in {"memory", "sqlite"}:
        raise typer.BadParameter("Use --session-state-store memory or sqlite.")
    if revoke_file and not revoke_file.exists():
        raise typer.BadParameter(f"Emergency revoke file does not exist: {revoke_file}")
    if fallback_policy and not fallback_policy.exists():
        raise typer.BadParameter(f"Fallback policy file does not exist: {fallback_policy}")
    if rollout_policy and not rollout_policy.exists():
        raise typer.BadParameter(f"Rollout policy file does not exist: {rollout_policy}")
    if rollout_mode not in {"shadow", "enforce"}:
        raise typer.BadParameter("Use --rollout-mode shadow or enforce.")
    console.print(f"Session state: {'enabled' if monitor else 'disabled'}")
    console.print(f"Audit signing: {'enabled' if resolved_audit_signing_secret else 'disabled'}")
    console.print(f"Fallback policy: {fallback_policy if fallback_policy else 'disabled'}")
    console.print(f"Policy rollout: {'enabled' if rollout_policy else 'disabled'}")
    console.print("Endpoints: GET /health, POST /v1/check, /v1/tool/check, /v1/route, /v1/evaluate")
    serve_sidecar(
        policy_source,
        host=host,
        port=port,
        tool_policy_file=tool_policy_file,
        auth_token=resolved_auth_token,
        policy_auth_token=resolved_policy_auth_token,
        policy_cache_file=policy_cache if policy_url else None,
        policy_refresh_seconds=policy_refresh_seconds,
        policy_timeout_seconds=policy_timeout_seconds,
        policy_retry_base_seconds=policy_retry_base_seconds,
        policy_retry_max_seconds=policy_retry_max_seconds,
        policy_retry_jitter_seconds=policy_retry_jitter_seconds,
        fail_closed=not fail_open,
        session_monitor=monitor,
        emergency_revoke_file=revoke_file,
        policy_sha256=policy_sha256,
        fallback_policy_file=fallback_policy,
        audit_signing_secret=resolved_audit_signing_secret,
        policy_rollout=PolicyRollout.from_file(
            rollout_policy,
            mode=rollout_mode,  # type: ignore[arg-type]
            percentage=rollout_percentage,
        )
        if rollout_policy
        else None,
    )


@guards_app.command("list")
def list_guards(policy_file: Path) -> None:
    """List guards declared in a PolicyAware YAML policy."""
    if not policy_file.exists():
        raise typer.BadParameter(f"Policy file does not exist: {policy_file}")
    policy = yaml.safe_load(policy_file.read_text(encoding="utf-8")) or {}
    guards = policy.get("guards", {}) if isinstance(policy, dict) else {}
    table = Table(title=f"PolicyAware Guards: {policy_file}")
    table.add_column("Phase")
    table.add_column("Name")
    table.add_column("Config")
    table.add_column("When")
    for phase in ("input", "output"):
        for spec in guards.get(phase, []) if isinstance(guards, dict) else []:
            if not isinstance(spec, dict):
                continue
            config = spec.get("config_path") or spec.get("config") or spec.get("rail_spec") or "-"
            table.add_row(
                phase,
                str(spec.get("name", "")),
                str(config),
                json.dumps(spec.get("when", {}), sort_keys=True),
            )
    console.print(table)


@integrations_app.command("list")
def list_integrations(
    json_output: bool = typer.Option(False, "--json", help="Print integrations as JSON."),
) -> None:
    """List available PolicyAware integrations, install extras, and examples."""
    if json_output:
        console.print_json(data={"integrations": INTEGRATIONS})
        return
    table = Table(title="PolicyAware Integrations")
    table.add_column("Integration", style="bold")
    table.add_column("Status")
    table.add_column("Extra")
    table.add_column("Install")
    table.add_column("Example / Docs")
    for item in INTEGRATIONS:
        table.add_row(
            item["name"],
            item["status"],
            item["extra"],
            item["install"],
            item["example"],
        )
    console.print(table)
    console.print(
        "[dim]PolicyAware keeps external frameworks optional. "
        "Compatible integrations are not official endorsements unless stated.[/dim]"
    )


@integrations_app.command("recommend")
def recommend_integrations(
    path: Path = typer.Argument(
        Path("."),
        help="Project folder or file to inspect for integration signals.",
    ),
    use_case: str | None = typer.Option(
        None,
        "--use-case",
        help="Optional user hint, for example api, rag, agent, mcp, scan, compliance.",
    ),
    framework: str | None = typer.Option(
        None,
        "--framework",
        help="Optional framework hint, for example fastapi, langchain, langgraph, llamaindex, haystack.",
    ),
    needs: str | None = typer.Option(
        None,
        "--needs",
        help='Optional comma/space-separated needs, for example "pii audit citations tools cost".',
    ),
    top: int = typer.Option(3, "--top", help="Number of recommendations to show."),
    json_output: bool = typer.Option(False, "--json", help="Print recommendation report as JSON."),
    html_out: Path | None = typer.Option(
        None,
        "--html",
        help="Optional HTML recommendation report output path.",
    ),
) -> None:
    """Recommend the best PolicyAware integration from project signals and user hints."""
    if not path.exists():
        raise typer.BadParameter(f"Path does not exist: {path}")
    report = IntegrationRecommender().recommend(
        path,
        use_case=use_case,
        framework=framework,
        needs=needs,
    )
    if json_output:
        console.print_json(data=report.to_dict())
        if html_out:
            console.print(f"HTML report: {report.write_html(html_out)}")
        return
    if html_out:
        console.print(f"[bold green]HTML report:[/bold green] {report.write_html(html_out)}")

    signals = report.signals
    console.print(
        Panel(
            (
                f"[bold]Scanned:[/bold] {report.scanned_path}\n"
                f"[bold]Files sampled:[/bold] {signals['files_sampled']}\n"
                f"[bold]Hints:[/bold] use_case={signals['hints']['use_case'] or '-'}, "
                f"framework={signals['hints']['framework'] or '-'}, "
                f"needs={', '.join(signals['hints']['needs']) or '-'}"
            ),
            title="PolicyAware Integration Recommender",
            border_style="cyan",
        )
    )

    table = Table(title="Recommended Integrations", box=box.SIMPLE_HEAVY)
    table.add_column("Rank", no_wrap=True)
    table.add_column("Integration", style="bold")
    table.add_column("Confidence", justify="right")
    table.add_column("Why")
    table.add_column("Install")
    table.add_column("Example")
    for index, item in enumerate(report.recommendations[:top], start=1):
        table.add_row(
            str(index),
            item.name,
            f"{item.confidence:.2f}",
            "; ".join(item.reasons) or "Default recommendation.",
            item.install,
            item.example,
        )
    console.print(table)

    if report.best:
        steps = Table(title=f"Next Steps For {report.best.name}", box=box.SIMPLE)
        steps.add_column("#", no_wrap=True)
        steps.add_column("Step")
        for index, step in enumerate(report.best.next_steps, start=1):
            steps.add_row(str(index), step)
        console.print(steps)
        console.print(f"[bold]Docs:[/bold] {report.best.docs}")


@examples_app.command("list")
def list_examples(json_output: bool = typer.Option(False, "--json", help="Print examples as JSON.")) -> None:
    """List bundled PolicyAware examples and runnable commands."""
    if json_output:
        console.print_json(data={"examples": EXAMPLES})
        return
    table = Table(title="PolicyAware Examples")
    table.add_column("Example")
    table.add_column("Command")
    table.add_column("Description")
    for item in EXAMPLES:
        table.add_row(
            str(item["id"]),
            f"policyaware examples run {item['id']}",
            str(item["description"]),
        )
    console.print(table)


@examples_app.command("run")
def run_example(example_id: str) -> None:
    """Run a known bundled example from the local repository checkout."""
    example = _example_by_id(example_id)
    if example is None:
        raise typer.BadParameter(f"Unknown example: {example_id}. Run `policyaware examples list`.")
    examples_root = _examples_root()
    example_dir = examples_root / str(example["id"])
    if not example_dir.exists():
        raise typer.BadParameter(f"Example folder not found: {example_dir}")
    command = [sys.executable, *[str(part) for part in example["command"]]]
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    console.print(f"[bold]Running:[/bold] {' '.join(command)}")
    result = subprocess.run(command, cwd=example_dir, env=env, check=False)
    raise typer.Exit(code=result.returncode)


@contract_app.command("check")
def contract_check(
    path: Path = typer.Argument(..., help="Python source folder or file to scan."),
    policy_file: Path = typer.Option(..., "--policy", help="Tool-governance YAML policy file."),
    json_output: bool = typer.Option(False, "--json", help="Print contract report as JSON."),
    fail_on: str = typer.Option("high", "--fail-on", help="Fail on severity: high, critical, none."),
) -> None:
    """Check YAML tool policies against Python function contracts."""
    report = PolicyContractChecker().check(path, policy_file)
    if json_output:
        console.print_json(data=report.to_dict())
    else:
        table = Table(title="PolicyAware Contract Check")
        table.add_column("Status")
        table.add_column("Connector")
        table.add_column("Action")
        table.add_column("Finding")
        table.add_column("Recommendation")
        for finding in report.findings:
            status = {
                "critical": "[red]CRITICAL[/red]",
                "high": "[red]HIGH[/red]",
                "medium": "[yellow]MEDIUM[/yellow]",
                "low": "[yellow]LOW[/yellow]",
                "info": "[green]PASS[/green]",
            }.get(finding.severity, finding.severity.upper())
            table.add_row(
                status,
                finding.connector_id,
                finding.action,
                f"{finding.title} {finding.detail}",
                finding.recommendation,
            )
        console.print(table)
    if _contract_should_fail(fail_on, report):
        raise typer.Exit(code=1)


@contract_app.command("export")
def contract_export(
    path: Path = typer.Argument(..., help="Python source folder or file to scan."),
    out: Path = typer.Option(Path("policyaware-tool-contracts.json"), "--out", "-o", help="Output JSON path."),
) -> None:
    """Export discovered Python tool contracts to JSON."""
    written = PolicyContractChecker().export(path, out)
    console.print(f"[bold green]Exported tool contracts:[/bold green] {written}")


@policy_app.command("pull")
def pull_policy(
    source: str = typer.Argument(
        ...,
        help="Local path, HTTP(S), S3, GCS, or ADLS Gen2 URI to a PolicyAware YAML policy.",
    ),
    out: Path = typer.Option(Path("policyaware.yaml"), "--out", "-o", help="Output policy YAML path."),
    auth_token: str | None = typer.Option(
        None,
        "--auth-token",
        help="Optional bearer token or SAS token for remote policy sources.",
    ),
    auth_env: str = typer.Option(
        "POLICYAWARE_POLICY_TOKEN",
        "--auth-env",
        help="Environment variable used for remote policy source auth.",
    ),
    cache: Path | None = typer.Option(
        None,
        "--cache",
        help="Optional cache path used when HTTP(S) source is temporarily unavailable.",
    ),
    expected_sha256: str | None = typer.Option(
        None,
        "--sha256",
        help="Expected SHA256 checksum for the policy source.",
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite output file if it exists."),
) -> None:
    """Pull and validate a policy from a local file or central HTTP(S) source."""
    if out.exists() and not force:
        raise typer.BadParameter(f"Output already exists: {out}. Use --force to overwrite.")
    resolved_auth_token = auth_token or os.getenv(auth_env)
    policy_source = policy_source_from_uri(
        source,
        auth_token=resolved_auth_token,
        cache_file=cache,
        expected_sha256=expected_sha256,
    )
    snapshot = policy_source.load()
    PolicyEngine(snapshot.policy)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml.safe_dump(snapshot.policy, sort_keys=False), encoding="utf-8")
    console.print(f"[bold green]Pulled policy:[/bold green] {snapshot.source}")
    console.print(f"Version: {snapshot.version}")
    console.print(f"SHA256: {snapshot.sha256}")
    console.print(f"Written: {out.resolve()}")


@policy_app.command("validate")
def validate_policy(policy_file: Path) -> None:
    """Validate a YAML policy file and print clear schema errors."""
    import yaml

    with policy_file.open("r", encoding="utf-8") as handle:
        policy = yaml.safe_load(handle) or {}
    try:
        PolicySchemaValidator().validate(policy)
    except PolicyValidationError as exc:
        console.print("[bold red]Policy validation failed[/bold red]")
        for error in exc.errors:
            console.print(f"- {error}")
        raise typer.Exit(code=1) from exc
    console.print("[bold green]Policy validation passed[/bold green]")


@policy_app.command("migrate")
def migrate_policy(
    policy_file: Path,
    out: Path | None = typer.Option(None, "--out", "-o", help="Output path for migrated policy."),
    to_version: str = typer.Option("0.3", "--to", help="Target schema version annotation."),
    force: bool = typer.Option(False, "--force", help="Overwrite output file if it exists."),
) -> None:
    """Conservatively annotate and normalize a policy for a target schema version."""
    if not policy_file.exists():
        raise typer.BadParameter(f"Policy file does not exist: {policy_file}")
    target = out or policy_file.with_name(f"{policy_file.stem}.schema-{to_version}{policy_file.suffix}")
    if target.exists() and not force:
        raise typer.BadParameter(f"Output already exists: {target}. Use --force to overwrite.")
    policy = yaml.safe_load(policy_file.read_text(encoding="utf-8")) or {}
    if not isinstance(policy, dict):
        raise typer.BadParameter("Policy file must contain a YAML mapping/object.")
    migrated = _migrated_policy(policy, to_version)
    target.write_text(yaml.safe_dump(migrated, sort_keys=False), encoding="utf-8")
    console.print(f"[bold green]Migrated policy written:[/bold green] {target}")
    console.print(
        "Migration is conservative: schema_version/default/rules are normalized only. "
        "Review before production."
    )
    console.print("Review the migration note and run:")
    console.print(f"  policyaware policy validate {target}")


@policy_app.command("compose")
def compose_policy(
    manifest: Path = typer.Argument(..., help="Policy composition manifest YAML."),
    out: Path = typer.Option(
        Path("policyaware.composed.yaml"),
        "--out",
        "-o",
        help="Output path for the composed policy.",
    ),
    strict: bool = typer.Option(
        True,
        "--strict/--no-strict",
        help="Fail when lower-precedence broadening conflicts are detected.",
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite output file if it exists."),
    json_output: bool = typer.Option(False, "--json", help="Print composition report as JSON."),
) -> None:
    """Compose global, compliance, tenant, app, and local policy layers deterministically."""
    if not manifest.exists():
        raise typer.BadParameter(f"Manifest does not exist: {manifest}")
    if out.exists() and not force:
        raise typer.BadParameter(f"Output already exists: {out}. Use --force to overwrite.")
    try:
        report = PolicyComposer(strict=strict).compose(load_policy_layers(manifest))
    except PolicyCompositionError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if json_output:
        console.print_json(data=report.to_dict())
    else:
        _render_policy_composition_report(report)
    if report.has_errors:
        raise typer.Exit(code=1)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml.safe_dump(report.composed_policy, sort_keys=False), encoding="utf-8")
    console.print(f"[bold green]Composed policy written:[/bold green] {out.resolve()}")
    console.print(f"Validate it with: policyaware policy validate {out}")


@policy_app.command("compose-check")
def compose_check_policy(
    manifest: Path = typer.Argument(..., help="Policy composition manifest YAML."),
    strict: bool = typer.Option(
        True,
        "--strict/--no-strict",
        help="Report lower-precedence broadening conflicts as errors.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Print composition report as JSON."),
) -> None:
    """Validate policy hierarchy and override conflicts without writing a composed policy."""
    if not manifest.exists():
        raise typer.BadParameter(f"Manifest does not exist: {manifest}")
    try:
        report = PolicyComposer(strict=strict).compose(load_policy_layers(manifest))
    except PolicyCompositionError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if json_output:
        console.print_json(data=report.to_dict())
    else:
        _render_policy_composition_report(report)
    if report.has_errors:
        raise typer.Exit(code=1)


@policy_packs_app.command("list")
def list_packs(json_output: bool = typer.Option(False, "--json", help="Print policy packs as JSON.")) -> None:
    """List bundled compliance-oriented starter policy packs."""
    packs = list_policy_packs()
    if json_output:
        console.print_json(data={"policy_packs": [pack.__dict__ for pack in packs]})
        return
    table = Table(title="PolicyAware Policy Packs")
    table.add_column("Pack")
    table.add_column("Description")
    table.add_column("Compliance Note")
    for pack in packs:
        table.add_row(pack.id, pack.description, pack.compliance_note)
    console.print(table)


@policy_packs_app.command("show")
def show_pack(pack_id: str) -> None:
    """Print a bundled policy pack YAML template."""
    try:
        console.print(read_policy_pack(pack_id))
    except KeyError as exc:
        raise typer.BadParameter(str(exc)) from exc


@policy_packs_app.command("copy")
def copy_pack(
    pack_id: str,
    out: Path = typer.Option(Path("policyaware.yaml"), "--out", "-o", help="Output policy YAML path."),
    force: bool = typer.Option(False, "--force", help="Overwrite the output file if it exists."),
) -> None:
    """Copy a bundled starter policy pack to a local YAML file."""
    try:
        written = copy_policy_pack(pack_id, out, force=force)
    except KeyError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except FileExistsError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"[bold green]Copied policy pack:[/bold green] {pack_id} -> {written}")
    console.print(f"Validate it with: policyaware policy validate {written}")


@policy_app.command("test")
def test_policy(
    policy_file: Path,
    role: str = "support_agent",
    tenant: str = "acme",
    region: str = "us",
    risk: str = "low",
    prompt: str = "Summarize this customer request.",
) -> None:
    """Evaluate a sample request against a YAML policy file."""
    engine = PolicyEngine.from_file(policy_file)
    gateway = Gateway(policy_engine=engine)
    response = gateway.chat(
        GatewayRequest(
            tenant=tenant,
            app="cli-policy-test",
            user={"id": "cli_user", "role": role},
            context={"region": region, "risk": risk, "task_type": "policy_test"},
            messages=[{"role": "user", "content": prompt}],
        )
    )

    table = Table(title="Policy Decision")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("decision", response.policy.decision.value)
    table.add_row("risk_tier", response.policy.risk_tier.value)
    table.add_row("reason", response.policy.reason)
    table.add_row("reason_codes", ", ".join(response.policy.reason_codes) or "-")
    table.add_row("matched_rules", ", ".join(response.policy.matched_rules) or "-")
    table.add_row("actions", ", ".join(response.policy.actions) or "-")
    table.add_row("trace_id", response.trace_id)
    console.print(table)


@policy_app.command("explain")
def explain_policy(
    policy_file: Path,
    role: str = "support_agent",
    tenant: str = "acme",
    region: str = "us",
    risk: str = "low",
    prompt: str = "Summarize this customer request.",
) -> None:
    """Render a machine-readable explanation for a sample policy decision."""
    gateway = Gateway.from_policy_file(policy_file)
    response = gateway.chat(
        GatewayRequest(
            tenant=tenant,
            app="cli-policy-explain",
            user={"id": "cli_user", "role": role},
            context={"region": region, "risk": risk, "task_type": "policy_explain"},
            messages=[{"role": "user", "content": prompt}],
        )
    )
    console.print_json(data=response.policy.explanation.model_dump(mode="json"))


@eval_app.command("run")
def run_eval(eval_file: Path, policy_file: Path | None = None) -> None:
    """Parse an evaluation suite and report configured checks."""
    gateway = Gateway.from_policy_file(policy_file) if policy_file else None
    result = EvalSuiteRunner().run_file(eval_file, gateway=gateway)
    console.print_json(data=result)


@risk_app.command("classify")
def classify_risk(
    prompt: str,
    role: str = "support_agent",
    domain: str = "support",
    autonomy: str = "assistive",
    action_type: str = "read",
) -> None:
    """Classify request risk without calling a model."""
    request = GatewayRequest(
        tenant="cli",
        app="risk-classifier",
        user={"id": "cli_user", "role": role},
        context={"domain": domain, "autonomy": autonomy, "action_type": action_type},
        messages=[{"role": "user", "content": prompt}],
    )
    findings = DataProtectionEngine().inspect(prompt)
    risk = RiskClassifier().classify(request, findings)
    console.print_json(data=risk.model_dump(mode="json"))


@tools_app.command("check")
def check_tool(
    policy_file: Path,
    agent: str = typer.Option(..., "--agent", help="Agent identity requesting the tool call."),
    connector: str = typer.Option(..., "--connector", help="Tool connector id."),
    action: str = typer.Option(..., "--action", help="Connector action name."),
    role: str = "developer",
) -> None:
    """Check whether an agent can call a governed tool action."""
    engine = ToolPolicyEngine.from_file(policy_file)
    decision = engine.decide(
        ToolCallRequest(
            agent_id=agent,
            connector_id=connector,
            action=action,
            user={"id": "cli_user", "role": role},
        )
    )
    console.print_json(data=decision.model_dump(mode="json"))


@audit_app.command("bundle")
def audit_bundle(
    trace_id: str,
    traces_file: Path = Path(".policyaware/traces.jsonl"),
    out: Path = Path(".policyaware/audit-bundle"),
) -> None:
    """Create JSON and Markdown evidence artifacts for a trace."""
    logger = AuditLogger(traces_file)
    trace = logger.find_trace(trace_id)
    if trace is None:
        raise typer.BadParameter(f"Trace not found: {trace_id}")
    written = AuditBundleWriter().write(trace, out)
    for path in written:
        console.print(str(path))


@audit_app.command("view")
def audit_view(
    traces_file: Path = typer.Argument(Path(".policyaware/traces.jsonl")),
    out: Path = Path(".policyaware/trace-viewer.html"),
) -> None:
    """Generate a static HTML trace viewer from JSONL audit traces."""
    traces = AuditLogger(traces_file).read_traces()
    output = TraceViewer().write_html(traces, out)
    console.print(str(output))


@audit_app.command("view-sqlite")
def audit_view_sqlite(
    db: Path = Path(".policyaware/audit.db"),
    out: Path = Path(".policyaware/trace-viewer.html"),
) -> None:
    """Generate a static HTML trace viewer from SQLite audit storage."""
    traces = SQLiteAuditLogger(db).read_traces()
    output = TraceViewer().write_html(traces, out)
    console.print(str(output))


@audit_app.command("dashboard")
def audit_dashboard(
    traces_file: Path = typer.Argument(Path(".policyaware/traces.jsonl")),
    out: Path = Path(".policyaware/governance-dashboard.html"),
) -> None:
    """Generate a static governance dashboard from JSONL audit traces."""
    traces = AuditLogger(traces_file).read_traces()
    output = GovernanceDashboard().write_html(traces, out)
    console.print(str(output))


@audit_app.command("dashboard-sqlite")
def audit_dashboard_sqlite(
    db: Path = Path(".policyaware/audit.db"),
    out: Path = Path(".policyaware/governance-dashboard.html"),
) -> None:
    """Generate a static governance dashboard from SQLite audit storage."""
    traces = SQLiteAuditLogger(db).read_traces()
    output = GovernanceDashboard().write_html(traces, out)
    console.print(str(output))


@audit_app.command("replay")
def replay_trace(
    trace_id: str,
    policy_file: Path,
    traces_file: Path = Path(".policyaware/traces.jsonl"),
) -> None:
    """Replay a stored request snapshot against a policy file without external model calls."""
    trace = AuditLogger(traces_file).find_trace(trace_id)
    if trace is None:
        raise typer.BadParameter(f"Trace not found: {trace_id}")
    gateway = Gateway.from_policy_file(policy_file)
    request = GatewayRequest(**trace["request_snapshot"])
    response = gateway.chat(request)
    console.print_json(
        data={
            "trace_id": trace_id,
            "original_decision": trace.get("policy_decision"),
            "replay_decision": response.policy.decision.value,
            "replay_reason_codes": response.policy.reason_codes,
            "changed": trace.get("policy_decision") != response.policy.decision.value,
        }
    )


@observability_app.command("prometheus")
def export_prometheus(
    traces_file: Path = typer.Argument(Path(".policyaware/traces.jsonl")),
    out: Path = Path(".policyaware/metrics.prom"),
) -> None:
    """Export local audit traces as Prometheus text exposition metrics."""
    traces = AuditLogger(traces_file).read_traces()
    output = PrometheusExporter().write(traces, out)
    console.print(str(output))


@observability_app.command("otel-json")
def export_otel_json(
    traces_file: Path = typer.Argument(Path(".policyaware/traces.jsonl")),
    out: Path = Path(".policyaware/otel-spans.json"),
) -> None:
    """Export local audit traces as OpenTelemetry-shaped JSON spans."""
    traces = AuditLogger(traces_file).read_traces()
    output = OpenTelemetryJsonExporter().write(traces, out)
    console.print(str(output))


@app.command("chat")
def chat(
    policy_file: Path,
    prompt: str,
    role: str = "support_agent",
    tenant: str = "acme",
    risk: str = "low",
) -> None:
    """Send a prompt through the local simulated gateway."""
    gateway = Gateway.from_policy_file(policy_file)
    response = gateway.chat(
        GatewayRequest(
            tenant=tenant,
            app="cli-chat",
            user={"id": "cli_user", "role": role},
            context={"region": "us", "risk": risk, "task_type": "chat"},
            messages=[{"role": "user", "content": prompt}],
        )
    )
    console.print(response.model_dump_json(indent=2))


@app.command("scan")
def scan_code(
    path: Path = typer.Argument(..., help="Local folder or file to scan."),
    out: Path = typer.Option(
        Path("policyaware-scan-report.html"),
        "--out",
        "-o",
        help="HTML report output path.",
    ),
    workers: int = typer.Option(
        0,
        "--workers",
        "-w",
        help="Parallel scanner workers. Use 0 for CPU count capped at 8.",
    ),
    max_file_size: str = typer.Option(
        "512kb",
        "--max-file-size",
        help="Skip files larger than this size, such as 512kb or 1mb.",
    ),
    json_out: Path | None = typer.Option(
        None,
        "--json",
        help="Optional machine-readable JSON report output path.",
    ),
    sarif_out: Path | None = typer.Option(
        None,
        "--sarif",
        help="Optional SARIF report output path for code scanning integrations.",
    ),
    markdown_out: Path | None = typer.Option(
        None,
        "--markdown",
        "--md",
        help="Optional Markdown report output path for PRs or review tickets.",
    ),
    formats: str = typer.Option(
        "html",
        "--format",
        help='Comma-separated output formats: "html", "json", "sarif", "markdown", or "html,json,sarif,markdown".',
    ),
    config_file: Path | None = typer.Option(
        None,
        "--config",
        help="Optional PolicyAware scan config YAML file.",
    ),
    ruleset: str = typer.Option(
        "all",
        "--ruleset",
        help=(
            "Built-in focus preset: all, ai-agent-security, prompt-injection, "
            "secrets, mcp-security, or enterprise-governance."
        ),
    ),
    diff: bool = typer.Option(
        False,
        "--diff",
        help="Scan only files changed relative to --diff-base.",
    ),
    diff_base: str = typer.Option(
        "HEAD",
        "--diff-base",
        help="Git ref used by --diff, for example HEAD, main, or origin/main.",
    ),
    fail_on: str = typer.Option(
        "none",
        "--fail-on",
        help="Exit with code 1 when findings at this severity or higher exist: critical, high, medium, low, none.",
    ),
    include: str | None = typer.Option(
        None,
        "--include",
        help='Comma-separated extensions to scan, for example ".py,.yaml,.json".',
    ),
    exclude: str | None = typer.Option(
        None,
        "--exclude",
        help='Comma-separated directory names to exclude in addition to defaults, for example "tests,fixtures".',
    ),
    ignore_file: Path | None = typer.Option(
        None,
        "--ignore-file",
        help="Optional .policyawareignore file with path globs to skip.",
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        help="Optional baseline JSON file of known finding fingerprints to ignore.",
    ),
    write_baseline: Path | None = typer.Option(
        None,
        "--write-baseline",
        help="Write current finding fingerprints to a baseline JSON file after scanning.",
    ),
    open_report: bool = typer.Option(False, "--open", help="Open the HTML report after scanning."),
) -> None:
    """Fast local AI governance scan with a user-friendly HTML report."""
    if not path.exists():
        raise typer.BadParameter(f"Path does not exist: {path}")
    exclude_dirs = set(LocalCodeScanner.DEFAULT_EXCLUDED_DIRS)
    exclude_dirs.update(_parse_csv(exclude) or [])
    default_ignore = path / ".policyawareignore" if path.is_dir() else path.parent / ".policyawareignore"
    ignore_patterns = _load_ignore_patterns(ignore_file or default_ignore)
    if config_file and ruleset != "all":
        raise typer.BadParameter("--config and a non-default --ruleset cannot be used together")
    try:
        config = ScanConfig.from_file(config_file) if config_file else ScanConfig.for_ruleset(ruleset)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    requested_formats = {item.lower() for item in (_parse_csv(formats) or ["html"])}
    if "json" in requested_formats and json_out is None:
        json_out = out.with_suffix(".json")
    if "sarif" in requested_formats and sarif_out is None:
        sarif_out = out.with_suffix(".sarif")
    if ({"markdown", "md"} & requested_formats) and markdown_out is None:
        markdown_out = out.with_suffix(".md")
    diff_files = git_changed_files(path if path.is_dir() else path.parent, diff_base) if diff else []
    scanner = LocalCodeScanner(
        include_extensions=_parse_csv(include),
        exclude_dirs=exclude_dirs,
        ignore_patterns=ignore_patterns,
        baseline_fingerprints=_load_baseline(baseline),
        config=config,
        diff_files=diff_files,
        workers=workers or None,
        max_file_size_bytes=_parse_size(max_file_size),
    )
    report = scanner.scan(
        path,
        out=out,
        json_out=json_out,
        sarif_out=sarif_out,
        markdown_out=markdown_out,
        open_report=open_report,
    )
    if write_baseline:
        _write_baseline(write_baseline, [finding.fingerprint for finding in report.findings])

    _render_scan_dashboard(
        report,
        json_out=json_out,
        sarif_out=sarif_out,
        markdown_out=markdown_out,
        write_baseline=write_baseline,
        diff=diff,
        diff_files=diff_files,
    )
    if _should_fail_scan(fail_on, dict(report.severity_counts)):
        raise typer.Exit(code=1)


@dev_app.command("simulate")
def simulate(policy_file: Path = Path("examples/policies/basic.yaml")) -> None:
    """Run local policy scenarios without external model calls."""
    scenarios = [
        ("low-risk allow", "support_agent", "low", "Summarize this ticket."),
        ("PII redaction", "support_agent", "low", "Email jane@example.com about the claim."),
        ("high-risk approval", "support_agent", "high", "Approve settlement without review."),
        ("deny unknown role", "intern", "low", "Summarize this ticket."),
    ]
    gateway = Gateway.from_policy_file(policy_file)
    table = Table(title="Local Simulation")
    table.add_column("Scenario")
    table.add_column("Decision")
    table.add_column("Risk")
    table.add_column("Actions")
    table.add_column("Matched Rules")
    for name, role, risk, prompt in scenarios:
        response = gateway.chat(
            GatewayRequest(
                tenant="acme",
                app="dev-sim",
                user={"id": role, "role": role},
                context={"region": "us", "risk": risk, "task_type": "simulation"},
                messages=[{"role": "user", "content": prompt}],
            )
        )
        table.add_row(
            name,
            response.policy.decision.value,
            response.policy.risk_tier.value,
            ", ".join(response.policy.actions) or "-",
            ", ".join(response.policy.matched_rules) or "-",
        )
    console.print(table)


if __name__ == "__main__":
    app()
