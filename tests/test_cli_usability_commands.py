from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from policyaware.cli import app


def test_doctor_cli_json() -> None:
    result = CliRunner().invoke(app, ["doctor", "--json"])

    assert result.exit_code == 0
    assert '"checks"' in result.output
    assert '"Python version"' in result.output


def test_doctor_validates_policy_file() -> None:
    result = CliRunner().invoke(app, ["doctor", "--policy", "examples/policies/basic.yaml"])

    assert result.exit_code == 0
    assert "PolicyAware Doctor" in result.output
    assert "Policy file" in result.output


def test_examples_list_cli() -> None:
    result = CliRunner().invoke(app, ["examples", "list", "--json"])

    assert result.exit_code == 0
    assert "langgraph-agent-governance" in result.output
    assert "enterprise-ai-control-plane" in result.output
    assert "mcp-policy-proxy-demo" in result.output


def test_examples_copy_cli(tmp_path: Path) -> None:
    out = tmp_path / "mcp-demo"

    result = CliRunner().invoke(app, ["examples", "copy", "mcp-policy-proxy-demo", str(out)])

    assert result.exit_code == 0
    assert (out / "mcp_proxy_demo.py").exists()
    assert (out / "README.md").exists()


def test_policy_migrate_writes_valid_yaml(tmp_path: Path) -> None:
    source = tmp_path / "policy.yaml"
    target = tmp_path / "policy.migrated.yaml"
    source.write_text(
        """
id: sample
default: deny
rules:
  - name: allow_developer
    effect: allow
    when:
      user.role_in: ["developer"]
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["policy", "migrate", str(source), "--out", str(target)])
    validate = CliRunner().invoke(app, ["policy", "validate", str(target)])

    assert result.exit_code == 0
    assert target.exists()
    assert "schema_version: '0.3'" in target.read_text(encoding="utf-8")
    assert validate.exit_code == 0


def test_policy_diff_reports_changed_rules(tmp_path: Path) -> None:
    old = tmp_path / "old.yaml"
    new = tmp_path / "new.yaml"
    old.write_text(
        """
id: old
default: deny
rules:
  - name: deny_secret
    effect: deny
    when:
      data.contains_secrets: true
""",
        encoding="utf-8",
    )
    new.write_text(
        """
id: new
default: deny
rules:
  - name: redact_pii
    effect: transform
    action: redact
    when:
      data.contains_pii: true
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["policy", "diff", str(old), str(new), "--json"])

    assert result.exit_code == 0
    assert '"removed"' in result.output
    assert "deny_secret" in result.output
    assert "redact_pii" in result.output


def test_policy_diff_can_fail_on_relaxed_policy(tmp_path: Path) -> None:
    old = tmp_path / "old.yaml"
    new = tmp_path / "new.yaml"
    old.write_text(
        """
id: old
default: deny
rules:
  - name: deny_secret
    effect: deny
    when:
      data.contains_secrets: true
""",
        encoding="utf-8",
    )
    new.write_text(
        """
id: new
default: allow
rules: []
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["policy", "diff", str(old), str(new), "--fail-on-relaxed"])

    assert result.exit_code == 1


def test_policy_summarize_cli_json() -> None:
    result = CliRunner().invoke(app, ["policy", "summarize", "examples/policies/basic.yaml", "--json"])

    assert result.exit_code == 0
    assert '"default": "deny"' in result.output
    assert '"rule_count"' in result.output
    assert '"coverage"' in result.output


def test_policy_lint_flags_default_allow(tmp_path: Path) -> None:
    policy = tmp_path / "weak.yaml"
    policy.write_text(
        """
id: weak
default: allow
rules:
  - name: allow_everything
    effect: allow
    when: {}
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["policy", "lint", str(policy), "--json", "--fail-on", "high"])

    assert result.exit_code == 1
    assert "POLICY.DEFAULT_ALLOW" in result.output
    assert "POLICY.BROAD_ALLOW" in result.output


def test_policy_normalize_writes_stable_yaml(tmp_path: Path) -> None:
    source = tmp_path / "policy.yaml"
    target = tmp_path / "policy.normalized.yaml"
    source.write_text(
        """
rules:
  - when:
      user.role: developer
    effect: allow
    name: allow_developer
default: deny
id: sample
schema_version: "0.3"
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["policy", "normalize", str(source), "--out", str(target)])

    assert result.exit_code == 0
    normalized = target.read_text(encoding="utf-8")
    assert normalized.index("id: sample") < normalized.index("default: deny")
    assert normalized.index("name: allow_developer") < normalized.index("effect: allow")


def test_policy_checklist_reports_readiness_json() -> None:
    result = CliRunner().invoke(app, ["policy", "checklist", "examples/policies/basic.yaml", "--json"])

    assert result.exit_code == 0
    assert '"checklist"' in result.output
    assert '"deny_by_default"' in result.output
    assert '"counts"' in result.output


def test_policy_checklist_can_fail_on_weak_policy(tmp_path: Path) -> None:
    policy = tmp_path / "weak.yaml"
    policy.write_text(
        """
id: weak
default: allow
rules: []
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["policy", "checklist", str(policy), "--fail-on", "high"])

    assert result.exit_code == 1
    assert "PolicyAware Policy Readiness Checklist" in result.output
    assert "Policy defaults to deny" in result.output


def test_policy_doctor_reports_rollup_json() -> None:
    result = CliRunner().invoke(app, ["policy", "doctor", "examples/policies/basic.yaml", "--json"])

    assert result.exit_code == 0
    assert '"lint"' in result.output
    assert '"readiness"' in result.output
    assert '"summary"' in result.output


def test_policy_doctor_can_fail_on_weak_policy(tmp_path: Path) -> None:
    policy = tmp_path / "weak.yaml"
    policy.write_text(
        """
id: weak
default: allow
rules: []
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["policy", "doctor", str(policy), "--fail-on", "high"])

    assert result.exit_code == 1
    assert "PolicyAware policy doctor" in result.output
    assert "POLICY.DEFAULT_ALLOW" in result.output


def test_demo_doctor_writes_policy_and_runs_doctor(tmp_path: Path) -> None:
    out = tmp_path / "demo-policy.yaml"

    result = CliRunner().invoke(app, ["demo", "doctor", "--out", str(out)])

    assert result.exit_code == 0
    assert out.exists()
    assert "Created demo policy" in result.output
    assert "PASS PolicyAware policy doctor" in result.output
    assert "POLICY.SCHEMA_INVALID" not in result.output
    assert "PolicyAware policy doctor" in result.output
    text = out.read_text(encoding="utf-8")
    assert "policyaware_demo_doctor" in text
    assert "block_secrets" in text


def test_demo_doctor_json_output(tmp_path: Path) -> None:
    out = tmp_path / "demo-policy.yaml"

    result = CliRunner().invoke(app, ["demo", "doctor", "--out", str(out), "--json"])

    assert result.exit_code == 0
    assert '"policy_file"' in result.output
    assert '"policyaware_demo_doctor"' in result.output
    assert '"readiness"' in result.output


def test_demo_doctor_refuses_overwrite_without_force(tmp_path: Path) -> None:
    out = tmp_path / "demo-policy.yaml"
    out.write_text("id: existing\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["demo", "doctor", "--out", str(out)])

    assert result.exit_code != 0
    assert "Use --force to overwrite" in result.output


def test_protect_redact_cli_json() -> None:
    result = CliRunner().invoke(app, ["protect", "redact", "Email jane@example.com", "--json"])

    assert result.exit_code == 0
    assert "[REDACTED_EMAIL]" in result.output
    assert '"contains_pii": true' in result.output


def test_protect_inspect_cli_json() -> None:
    result = CliRunner().invoke(app, ["protect", "inspect", "Email jane@example.com", "--json"])

    assert result.exit_code == 0
    assert '"contains_pii": true' in result.output
    assert '"email"' in result.output


def test_integration_recommend_html_output(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "graph.py").write_text("from langgraph.graph import StateGraph\n", encoding="utf-8")
    report = tmp_path / "integration-report.html"

    result = CliRunner().invoke(
        app,
        ["integrations", "recommend", str(project), "--html", str(report)],
    )

    assert result.exit_code == 0
    assert report.exists()
    assert "PolicyAware Integration Recommendation Report" in report.read_text(encoding="utf-8")


def test_examples_run_unknown_fails_helpfully() -> None:
    result = CliRunner().invoke(app, ["examples", "run", "missing-example"])

    assert result.exit_code != 0
    assert "Unknown example" in result.output


def test_policyaware_test_harness_cli_json() -> None:
    result = CliRunner().invoke(
        app,
        [
            "test-harness",
            "examples/policies/basic.yaml",
            "--requests",
            "20",
            "--workers",
            "2",
            "--json",
        ],
    )

    assert result.exit_code == 0
    assert '"requests": 20' in result.output
    assert '"passed": true' in result.output
