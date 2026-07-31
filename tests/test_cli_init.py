from pathlib import Path

import yaml
from typer.testing import CliRunner

from policyaware.cli import app
from policyaware.policy import PolicyEngine
from policyaware.policy_schema import PolicySchemaValidator


def test_init_creates_valid_baseline_policy(tmp_path: Path) -> None:
    out = tmp_path / "policyaware.yaml"

    result = CliRunner().invoke(app, ["init", "--out", str(out)])

    assert result.exit_code == 0
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "NIST-aligned" in text
    assert "default: deny" in text
    assert "deny_risky_mcp_tool_commands" in text
    assert "deny_excessive_token_budget" in text

    policy = yaml.safe_load(text)
    PolicySchemaValidator().validate(policy)
    assert PolicyEngine(policy) is not None


def test_init_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    out = tmp_path / "policyaware.yaml"
    out.write_text("existing: true\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["init", "--out", str(out)])

    assert result.exit_code == 1
    assert out.read_text(encoding="utf-8") == "existing: true\n"
    assert "Refusing to overwrite" in result.output


def test_init_force_overwrites_existing_policy(tmp_path: Path) -> None:
    out = tmp_path / "policyaware.yaml"
    out.write_text("existing: true\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["init", "--out", str(out), "--force"])

    assert result.exit_code == 0
    assert "policyaware_baseline_policy" in out.read_text(encoding="utf-8")


def test_init_rejects_unknown_profile(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        ["init", "--out", str(tmp_path / "policyaware.yaml"), "--profile", "healthcare"],
    )

    assert result.exit_code != 0
    assert "baseline" in result.output
