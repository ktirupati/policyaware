from __future__ import annotations

import json
from pathlib import Path

import typer
import yaml
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
from policyaware.scanner import LocalCodeScanner, ScanConfig, git_changed_files
from policyaware.tools import ToolPolicyEngine

app = typer.Typer(help="PolicyAware AI Gateway CLI")
policy_app = typer.Typer(help="Policy testing commands")
eval_app = typer.Typer(help="Evaluation commands")
dev_app = typer.Typer(help="Local development commands")
tools_app = typer.Typer(help="MCP and tool governance commands")
audit_app = typer.Typer(help="Audit and replay commands")
risk_app = typer.Typer(help="Risk classification commands")
observability_app = typer.Typer(help="Metrics and trace export commands")
guards_app = typer.Typer(help="Guardrails integration commands")
app.add_typer(policy_app, name="policy")
app.add_typer(eval_app, name="eval")
app.add_typer(dev_app, name="dev")
app.add_typer(tools_app, name="tools")
app.add_typer(audit_app, name="audit")
app.add_typer(risk_app, name="risk")
app.add_typer(observability_app, name="observability")
app.add_typer(guards_app, name="guards")
console = Console()


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
    config = ScanConfig.from_file(config_file) if config_file else ScanConfig()
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

    table = Table(title="PolicyAware Local Code Scan")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Overall risk", report.overall_risk)
    table.add_row("Files scanned", str(report.files_scanned))
    table.add_row("Files skipped", str(report.files_skipped))
    table.add_row("Findings", str(len(report.findings)))
    table.add_row("Critical", str(report.severity_counts["critical"]))
    table.add_row("High", str(report.severity_counts["high"]))
    table.add_row("Medium", str(report.severity_counts["medium"]))
    table.add_row("Low", str(report.severity_counts["low"]))
    table.add_row("Policy coverage", f"{report.policy_coverage_score}%")
    table.add_row("Suppressed findings", str(report.suppressed_findings))
    table.add_row("Baseline ignored", str(report.baseline_ignored))
    if diff:
        table.add_row("Diff files matched", str(len(diff_files)))
    table.add_row("Scan time", f"{report.duration_seconds:.2f}s")
    table.add_row("HTML report", report.output_path)
    if json_out:
        table.add_row("JSON report", str(json_out.resolve()))
    if sarif_out:
        table.add_row("SARIF report", str(sarif_out.resolve()))
    if markdown_out:
        table.add_row("Markdown report", str(markdown_out.resolve()))
    if write_baseline:
        table.add_row("Baseline written", str(write_baseline.resolve()))
    console.print(table)
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
