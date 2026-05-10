from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from policyaware.audit import AuditBundleWriter, AuditLogger, SQLiteAuditLogger, TraceViewer
from policyaware.data_protection import DataProtectionEngine
from policyaware.evals import EvalSuiteRunner
from policyaware.gateway import Gateway
from policyaware.models import GatewayRequest, ToolCallRequest
from policyaware.observability import OpenTelemetryJsonExporter, PrometheusExporter
from policyaware.policy import PolicyEngine
from policyaware.policy_schema import PolicySchemaValidator, PolicyValidationError
from policyaware.risk import RiskClassifier
from policyaware.tools import ToolPolicyEngine

app = typer.Typer(help="PolicyAware AI Gateway CLI")
policy_app = typer.Typer(help="Policy testing commands")
eval_app = typer.Typer(help="Evaluation commands")
dev_app = typer.Typer(help="Local development commands")
tools_app = typer.Typer(help="MCP and tool governance commands")
audit_app = typer.Typer(help="Audit and replay commands")
risk_app = typer.Typer(help="Risk classification commands")
observability_app = typer.Typer(help="Metrics and trace export commands")
app.add_typer(policy_app, name="policy")
app.add_typer(eval_app, name="eval")
app.add_typer(dev_app, name="dev")
app.add_typer(tools_app, name="tools")
app.add_typer(audit_app, name="audit")
app.add_typer(risk_app, name="risk")
app.add_typer(observability_app, name="observability")
console = Console()


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
    agent: str,
    connector: str,
    action: str,
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
    traces_file: Path = Path(".policyaware/traces.jsonl"),
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
    traces_file: Path = Path(".policyaware/traces.jsonl"),
    out: Path = Path(".policyaware/metrics.prom"),
) -> None:
    """Export local audit traces as Prometheus text exposition metrics."""
    traces = AuditLogger(traces_file).read_traces()
    output = PrometheusExporter().write(traces, out)
    console.print(str(output))


@observability_app.command("otel-json")
def export_otel_json(
    traces_file: Path = Path(".policyaware/traces.jsonl"),
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
