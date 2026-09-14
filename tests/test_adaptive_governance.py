from pathlib import Path

import yaml
from typer.testing import CliRunner

from policyaware import DataProtectionEngine, GatewayRequest, PlanPreflightChecker, PolicyEngine
from policyaware.cli import app
from policyaware.models import DataFindings
from policyaware.policy_schema import PolicySchemaValidator
from policyaware.scanner import LocalCodeScanner


def test_synthetic_redaction_preserves_useful_formats() -> None:
    result = DataProtectionEngine().synthesize(
        "Email krishna@example.com or call 212-555-7890 with card 4111 1111 1111 2222."
    )

    assert "krishna@example.com" not in result.synthetic_text
    assert "212-555-7890" not in result.synthetic_text
    assert "alex.morgan@example.com" in result.synthetic_text
    assert "415-555-0188" in result.synthetic_text
    assert result.synthetic_map["alex.morgan@example.com"] == "krishna@example.com"
    assert {"email", "phone", "credit_card"}.issubset(set(result.categories))


def test_policy_safe_rewrite_returns_auditable_state_mutation() -> None:
    engine = PolicyEngine(
        {
            "id": "safe_rewrite_test",
            "default": "deny",
            "rules": [
                {
                    "name": "rewrite_delete_actions",
                    "effect": "transform",
                    "action": "safe_rewrite",
                    "when": {"request.action_type": "delete"},
                },
                {
                    "name": "allow_developers",
                    "effect": "allow",
                    "when": {"user.role": "developer"},
                },
            ],
        }
    )
    decision = engine.decide(
        GatewayRequest(
            tenant="acme",
            app="agent",
            user={"role": "developer"},
            context={"action_type": "delete"},
            messages=[{"role": "user", "content": "delete the records"}],
        ),
        DataFindings(),
    )

    assert decision.decision.value == "conditional_allow"
    assert "safe_rewrite" in decision.actions
    assert decision.state_mutation is not None
    assert decision.state_mutation["type"] == "rewrite_context"
    assert "read-only" in decision.state_mutation["messages"][0]["content"]


def test_plan_preflight_detects_cascading_risk(tmp_path: Path) -> None:
    plan = tmp_path / "plan.yaml"
    plan.write_text(
        """
steps:
  - tool: database
    action: delete customer records
  - tool: deploy
    action: deploy production patch
  - tool: webhook
    action: send result to external url
""",
        encoding="utf-8",
    )

    report = PlanPreflightChecker().check_file(plan)

    assert report.allowed is False
    assert report.highest_severity == "critical"
    assert any(finding.title == "Cascading high-impact plan trajectory" for finding in report.findings)


def test_scan_detects_shadow_ai_patterns(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "subprocess.run(['pip', 'install', 'unknown-agent-tool'])",
                "tool_registry.register_tool(dynamic_tool)",
            ]
        ),
        encoding="utf-8",
    )

    report = LocalCodeScanner(workers=1).scan(tmp_path, out=tmp_path / "report.html")

    assert report.category_counts["Shadow AI Governance"] >= 1
    assert any("Dynamic code execution" in finding.title for finding in report.findings)


def test_policy_suggest_cli_generates_valid_policy(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "import openai",
                "client = openai.OpenAI()",
                "@tool",
                "def refund_customer(): pass",
                'prompt = "Email jane@example.com"',
            ]
        ),
        encoding="utf-8",
    )
    out = tmp_path / "policyaware.generated.yaml"

    result = CliRunner().invoke(
        app,
        ["policy", "suggest", str(tmp_path), "--out", str(out), "--force"],
    )

    assert result.exit_code == 0
    policy = yaml.safe_load(out.read_text(encoding="utf-8"))
    PolicySchemaValidator().validate(policy)
    actions = {rule.get("action") for rule in policy["rules"]}
    assert "synthetic_redact" in actions
    assert "safe_rewrite" in actions


def test_plan_and_protect_cli_commands(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text('{"steps": [{"tool": "db", "action": "delete rows"}]}', encoding="utf-8")

    plan_result = CliRunner().invoke(app, ["plan", "check", str(plan), "--fail-on", "critical"])
    protect_result = CliRunner().invoke(
        app,
        ["protect", "synthesize", "Email jane@example.com", "--json"],
    )

    assert plan_result.exit_code == 0
    assert "PolicyAware Plan Preflight" in plan_result.output
    assert protect_result.exit_code == 0
    assert "alex.morgan@example.com" in protect_result.output
