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
