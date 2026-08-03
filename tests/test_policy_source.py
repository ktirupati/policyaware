from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from policyaware import (
    AzureDataLakePolicySource,
    Gateway,
    GatewayRequest,
    GoogleCloudStoragePolicySource,
    S3PolicySource,
    parse_adls_uri,
    parse_gcs_uri,
    parse_s3_uri,
)
from policyaware.cli import app
from policyaware.policy_source import policy_source_from_uri


ALLOW_POLICY = """
default: deny
rules:
  - name: allow_support
    effect: allow
    when:
      user.role: support_agent
"""


DENY_POLICY = """
default: deny
rules:
  - name: emergency_revoke_support
    effect: deny
    when:
      user.role: support_agent
"""


def test_gateway_refreshes_dynamic_file_policy(tmp_path: Path) -> None:
    policy = tmp_path / "policyaware.yaml"
    policy.write_text(ALLOW_POLICY, encoding="utf-8")
    gateway = Gateway.from_policy_source(policy, refresh_seconds=0)
    request = GatewayRequest(
        tenant="acme",
        app="dynamic-policy-test",
        user={"role": "support_agent"},
        context={"region": "us", "risk": "low", "task_type": "support"},
        messages=[{"role": "user", "content": "Summarize this ticket."}],
    )

    allowed = gateway.chat(request)
    policy.write_text(DENY_POLICY, encoding="utf-8")
    denied = gateway.chat(request)

    assert allowed.policy.decision.value in {"allow", "conditional_allow"}
    assert denied.policy.decision.value == "deny"
    assert denied.policy.matched_rules == ["emergency_revoke_support"]


def test_policy_pull_cli_validates_and_writes_policy(tmp_path: Path) -> None:
    source = tmp_path / "central-policy.yaml"
    out = tmp_path / "policyaware.yaml"
    source.write_text(ALLOW_POLICY, encoding="utf-8")

    result = CliRunner().invoke(app, ["policy", "pull", str(source), "--out", str(out)])

    assert result.exit_code == 0
    assert out.exists()
    assert "allow_support" in out.read_text(encoding="utf-8")


def test_adls_gen2_uri_parsing() -> None:
    parsed = parse_adls_uri(
        "abfss://policy-configs@acmeai.dfs.core.windows.net/prod/policyaware.yaml"
    )

    assert parsed == {
        "account_url": "https://acmeai.dfs.core.windows.net",
        "file_system": "policy-configs",
        "file_path": "prod/policyaware.yaml",
    }


def test_policy_source_from_uri_supports_adls_gen2() -> None:
    source = policy_source_from_uri(
        "abfss://policy-configs@acmeai.dfs.core.windows.net/prod/policyaware.yaml",
        cache_file=".policyaware/policy-cache.yaml",
    )

    assert isinstance(source, AzureDataLakePolicySource)
    assert source.file_system == "policy-configs"
    assert source.file_path == "prod/policyaware.yaml"


def test_s3_uri_parsing_and_source_selection() -> None:
    parsed = parse_s3_uri("s3://policy-configs/prod/policyaware.yaml")
    source = policy_source_from_uri("s3://policy-configs/prod/policyaware.yaml")

    assert parsed == {"bucket": "policy-configs", "key": "prod/policyaware.yaml"}
    assert isinstance(source, S3PolicySource)
    assert source.bucket == "policy-configs"
    assert source.key == "prod/policyaware.yaml"


def test_gcs_uri_parsing_and_source_selection() -> None:
    parsed = parse_gcs_uri("gs://policy-configs/prod/policyaware.yaml")
    source = policy_source_from_uri("gs://policy-configs/prod/policyaware.yaml")

    assert parsed == {"bucket": "policy-configs", "blob": "prod/policyaware.yaml"}
    assert isinstance(source, GoogleCloudStoragePolicySource)
    assert source.bucket == "policy-configs"
    assert source.blob == "prod/policyaware.yaml"
