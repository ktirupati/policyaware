from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from policyaware import PolicyContractChecker
from policyaware.cli import app


def test_contract_check_passes_matching_tool_policy(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        """
def snowflake_query(database: str, sql: str):
    return []
""",
        encoding="utf-8",
    )
    policy = tmp_path / "tool-governance.yaml"
    policy.write_text(
        """
default: deny
connectors:
  - id: snowflake
    actions:
      query:
        effect: allow
        when:
          arguments.database_not_in: ["payroll"]
""",
        encoding="utf-8",
    )

    report = PolicyContractChecker().check(tmp_path, policy)

    assert report.passed is True
    assert report.findings[0].severity == "info"


def test_contract_check_detects_stale_argument_reference(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        """
def snowflake_query(catalog: str, sql: str):
    return []
""",
        encoding="utf-8",
    )
    policy = tmp_path / "tool-governance.yaml"
    policy.write_text(
        """
default: deny
connectors:
  - id: snowflake
    actions:
      query:
        effect: allow
        when:
          arguments.database_not_in: ["payroll"]
""",
        encoding="utf-8",
    )

    report = PolicyContractChecker().check(tmp_path, policy)

    assert report.passed is False
    assert report.findings[0].severity == "high"
    assert "database" in report.findings[0].detail
    assert "catalog" in report.findings[0].detail


def test_contract_check_detects_missing_tool_implementation(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text("def github_read_file(path: str): return ''\n", encoding="utf-8")
    policy = tmp_path / "tool-governance.yaml"
    policy.write_text(
        """
default: deny
connectors:
  - id: github
    actions:
      create_pr:
        effect: require_approval
""",
        encoding="utf-8",
    )

    report = PolicyContractChecker().check(tmp_path, policy)

    assert report.passed is False
    assert report.findings[0].title == "Policy action has no matching Python tool contract."


def test_contract_check_cli_json(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text("def crm_update_customer(customer_id: str): return None\n", encoding="utf-8")
    policy = tmp_path / "tool-governance.yaml"
    policy.write_text(
        """
default: deny
connectors:
  - id: crm
    actions:
      update_customer:
        effect: require_approval
        when:
          arguments.customer_id: "cust_123"
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        ["contract", "check", str(tmp_path), "--policy", str(policy), "--json"],
    )

    assert result.exit_code == 0
    assert '"passed": true' in result.output
    assert '"contracts_found": 1' in result.output


def test_contract_check_cli_fails_on_drift(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text("def crm_update_customer(account_id: str): return None\n", encoding="utf-8")
    policy = tmp_path / "tool-governance.yaml"
    policy.write_text(
        """
default: deny
connectors:
  - id: crm
    actions:
      update_customer:
        effect: require_approval
        when:
          arguments.customer_id: "cust_123"
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["contract", "check", str(tmp_path), "--policy", str(policy)])

    assert result.exit_code == 1
    assert "PolicyAware Contract Check" in result.output


def test_contract_export_cli(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text("def crm__read_customer(customer_id: str): return {}\n", encoding="utf-8")
    out = tmp_path / "contracts.json"

    result = CliRunner().invoke(app, ["contract", "export", str(tmp_path), "--out", str(out)])

    assert result.exit_code == 0
    assert out.exists()
    assert "read_customer" in out.read_text(encoding="utf-8")
