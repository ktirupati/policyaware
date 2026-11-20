from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from policyaware.cli import app


def test_cli_version_option() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.startswith("policyaware ")


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


def test_examples_list_compact_cli() -> None:
    result = CliRunner().invoke(app, ["examples", "list", "--compact"])

    assert result.exit_code == 0
    lines = result.output.strip().splitlines()
    assert "fastapi-llm-policy-middleware" in lines
    assert "mcp-policy-proxy-demo" in lines
    assert not any("policyaware examples run" in line for line in lines)


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


def test_policy_fingerprint_cli_is_stable_and_matches_runtime(tmp_path: Path) -> None:
    from policyaware.policy import policy_provenance

    policy_file = tmp_path / "policy.yaml"
    policy = {
        "id": "cli-fingerprint-test",
        "policy_version": "3",
        "schema_version": "0.4",
        "default": "deny",
        "rules": [],
    }
    policy_file.write_text(
        "id: cli-fingerprint-test\n"
        "policy_version: '3'\n"
        "schema_version: '0.4'\n"
        "default: deny\n"
        "rules: []\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["policy", "fingerprint", str(policy_file), "--json"])

    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["policy_id"] == "cli-fingerprint-test"
    assert output["policy_version"] == "3"
    assert output["policy_sha256"] == policy_provenance(policy)["policy_sha256"]


def test_policy_fingerprint_expected_hash_match_and_mismatch(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("id: approved\ndefault: deny\nrules: []\n", encoding="utf-8")
    fingerprint_result = CliRunner().invoke(
        app, ["policy", "fingerprint", str(policy_file), "--json"]
    )
    fingerprint = json.loads(fingerprint_result.output)["policy_sha256"]

    matched = CliRunner().invoke(
        app,
        [
            "policy",
            "fingerprint",
            str(policy_file),
            "--expected-sha256",
            fingerprint,
            "--json",
        ],
    )
    mismatched = CliRunner().invoke(
        app,
        [
            "policy",
            "fingerprint",
            str(policy_file),
            "--expected-sha256",
            "0" * 64,
            "--json",
        ],
    )

    assert matched.exit_code == 0
    assert json.loads(matched.output)["matches_expected"] is True
    assert mismatched.exit_code == 1
    assert json.loads(mismatched.output)["matches_expected"] is False


def test_policy_fingerprint_rejects_malformed_expected_hash(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("default: deny\nrules: []\n", encoding="utf-8")

    result = CliRunner().invoke(
        app,
        ["policy", "fingerprint", str(policy_file), "--expected-sha256", "not-a-hash"],
    )

    assert result.exit_code == 2


def test_policy_fingerprint_rejects_invalid_policy(tmp_path: Path) -> None:
    policy_file = tmp_path / "invalid.yaml"
    policy_file.write_text("default: maybe\nrules: []\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["policy", "fingerprint", str(policy_file), "--json"])

    assert result.exit_code != 0
    assert "Policy validation failed" in result.output


def test_policy_lock_create_and_verify_detects_policy_drift(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    lock_file = tmp_path / "policyaware.lock.json"
    policy_file.write_text(
        "id: locked-policy\ndefault: deny\nrules: []\n", encoding="utf-8"
    )

    created = CliRunner().invoke(
        app,
        ["policy", "lock", "create", str(policy_file), "--out", str(lock_file)],
    )
    verified = CliRunner().invoke(
        app,
        [
            "policy",
            "lock",
            "verify",
            str(policy_file),
            "--lock-file",
            str(lock_file),
            "--json",
        ],
    )

    assert created.exit_code == 0, created.output
    lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
    assert lock_data["lock_version"] == 1
    assert lock_data["policy"]["policy_id"] == "locked-policy"
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.output)["matches"] is True

    policy_file.write_text(
        "id: locked-policy\ndefault: allow\nrules: []\n", encoding="utf-8"
    )
    drift = CliRunner().invoke(
        app,
        [
            "policy",
            "lock",
            "verify",
            str(policy_file),
            "--lock-file",
            str(lock_file),
            "--json",
        ],
    )

    assert drift.exit_code == 1
    assert json.loads(drift.output)["matches"] is False


def test_policy_lock_create_requires_force_to_replace(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    lock_file = tmp_path / "policyaware.lock.json"
    policy_file.write_text("default: deny\nrules: []\n", encoding="utf-8")
    args = ["policy", "lock", "create", str(policy_file), "--out", str(lock_file)]

    assert CliRunner().invoke(app, args).exit_code == 0
    refused = CliRunner().invoke(app, args)
    replaced = CliRunner().invoke(app, [*args, "--force"])

    assert refused.exit_code != 0
    assert replaced.exit_code == 0


def test_policy_lock_update_requires_force_and_reports_both_fingerprints(
    tmp_path: Path,
) -> None:
    policy_file = tmp_path / "policy.yaml"
    lock_file = tmp_path / "policyaware.lock.json"
    policy_file.write_text("id: policy-a\ndefault: deny\nrules: []\n", encoding="utf-8")
    created = CliRunner().invoke(
        app,
        ["policy", "lock", "create", str(policy_file), "--out", str(lock_file)],
    )
    old_hash = json.loads(lock_file.read_text(encoding="utf-8"))["policy"]["policy_sha256"]
    policy_file.write_text("id: policy-a\ndefault: allow\nrules: []\n", encoding="utf-8")
    update_args = [
        "policy",
        "lock",
        "update",
        str(policy_file),
        "--lock-file",
        str(lock_file),
        "--json",
    ]

    refused = CliRunner().invoke(app, update_args)
    assert refused.exit_code != 0
    assert json.loads(lock_file.read_text(encoding="utf-8"))["policy"]["policy_sha256"] == old_hash

    updated = CliRunner().invoke(app, [*update_args, "--force"])

    assert created.exit_code == 0
    assert updated.exit_code == 0, updated.output
    result = json.loads(updated.output)
    current_hash = json.loads(lock_file.read_text(encoding="utf-8"))["policy"]["policy_sha256"]
    assert result["previous_sha256"] == old_hash
    assert result["updated_sha256"] == current_hash
    assert result["changed"] is True
    assert current_hash != old_hash

    verified = CliRunner().invoke(
        app,
        [
            "policy",
            "lock",
            "verify",
            str(policy_file),
            "--lock-file",
            str(lock_file),
            "--json",
        ],
    )
    assert verified.exit_code == 0


def test_policy_lock_update_reports_unchanged_fingerprint(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    lock_file = tmp_path / "policyaware.lock.json"
    policy_file.write_text("default: deny\nrules: []\n", encoding="utf-8")
    created = CliRunner().invoke(
        app,
        ["policy", "lock", "create", str(policy_file), "--out", str(lock_file)],
    )

    updated = CliRunner().invoke(
        app,
        [
            "policy",
            "lock",
            "update",
            str(policy_file),
            "--lock-file",
            str(lock_file),
            "--force",
            "--json",
        ],
    )

    assert created.exit_code == 0
    assert updated.exit_code == 0, updated.output
    result = json.loads(updated.output)
    assert result["changed"] is False
    assert result["previous_sha256"] == result["updated_sha256"]


def test_policy_lock_verify_rejects_malformed_lockfile(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    lock_file = tmp_path / "lock.json"
    policy_file.write_text("default: deny\nrules: []\n", encoding="utf-8")
    lock_file.write_text('{"lock_version": true, "policy": {}}', encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "policy",
            "lock",
            "verify",
            str(policy_file),
            "--lock-file",
            str(lock_file),
        ],
    )

    assert result.exit_code != 0


def test_policy_validate_json_success() -> None:
    result = CliRunner().invoke(app, ["policy", "validate", "examples/policies/basic.yaml", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert Path(payload["policy_file"]) == Path("examples/policies/basic.yaml")
    assert payload["errors"] == []


def test_policy_validate_json_failure(tmp_path: Path) -> None:
    policy = tmp_path / "invalid.yaml"
    policy.write_text(
        """
id: invalid
default: maybe
rules:
  - name: bad_effect
    effect: approve
    when:
      data.contains_pii: true
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["policy", "validate", str(policy), "--json"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert payload["policy_file"] == str(policy)
    assert payload["errors"]


def test_policy_validate_strict_fails_on_high_lint(tmp_path: Path) -> None:
    policy = tmp_path / "weak.yaml"
    policy.write_text(
        """
id: weak
default: allow
rules: []
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["policy", "validate", str(policy), "--strict"])

    assert result.exit_code == 1
    assert "Strict policy validation failed" in result.output
    assert "POLICY.DEFAULT_ALLOW" in result.output


def test_policy_validate_strict_json_includes_lint(tmp_path: Path) -> None:
    policy = tmp_path / "weak.yaml"
    policy.write_text(
        """
id: weak
default: allow
rules: []
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["policy", "validate", str(policy), "--strict", "--json"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert payload["strict"] is True
    assert payload["lint"]["counts"]["high"] >= 1


def test_policy_validate_github_format_outputs_annotations(tmp_path: Path) -> None:
    policy = tmp_path / "weak.yaml"
    policy.write_text(
        """
id: weak
default: allow
rules: []
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["policy", "validate", str(policy), "--strict", "--format", "github"])

    assert result.exit_code == 1
    assert "::error file=" in result.output
    assert "POLICY.DEFAULT_ALLOW" in result.output


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


def test_quickstart_writes_policy_and_runs_doctor(tmp_path: Path) -> None:
    out = tmp_path / "quickstart-policy.yaml"

    result = CliRunner().invoke(app, ["quickstart", "--out", str(out)])

    assert result.exit_code == 0
    assert out.exists()
    assert "Created demo policy" in result.output
    assert "PASS PolicyAware policy doctor" in result.output
    text = out.read_text(encoding="utf-8")
    assert "policyaware_demo_doctor" in text
    assert "block_secrets" in text


def test_quickstart_json_output(tmp_path: Path) -> None:
    out = tmp_path / "quickstart-policy.yaml"

    result = CliRunner().invoke(app, ["quickstart", "--out", str(out), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["policy_file"] == str(out)
    assert payload["readiness"]["ok"] is True


def test_quickstart_no_write_does_not_create_policy(tmp_path: Path) -> None:
    out = tmp_path / "quickstart-policy.yaml"

    result = CliRunner().invoke(app, ["quickstart", "--out", str(out), "--no-write"])

    assert result.exit_code == 0
    assert not out.exists()
    assert "Dry run" in result.output
    assert "PASS PolicyAware policy doctor" in result.output


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
