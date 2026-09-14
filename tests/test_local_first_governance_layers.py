from pathlib import Path

from typer.testing import CliRunner

from policyaware import (
    AirGapReadinessChecker,
    DriftCanaryCase,
    DriftCanaryEngine,
    FairnessMonitor,
    PolicyTranslationEngine,
)
from policyaware.cli import app


def test_airgap_checker_fails_remote_policy_and_model(tmp_path: Path) -> None:
    policy = tmp_path / "policyaware.yaml"
    policy.write_text("id: local\ndefault: deny\nrules: []\n", encoding="utf-8")

    report = AirGapReadinessChecker().check(
        policy_sources=[policy, "s3://bucket/policy.yaml"],
        model_sources=["local", "openai"],
    )

    assert report.ready is False
    assert any(finding.code == "AIRGAP.REMOTE_POLICY_SOURCE" for finding in report.findings)
    assert any(finding.code == "AIRGAP.REMOTE_MODEL_SOURCE" for finding in report.findings)


def test_policy_translation_generates_framework_recipes() -> None:
    report = PolicyTranslationEngine().translate(
        {"id": "enterprise_policy", "default": "deny", "rules": []},
        policy_file="policyaware.yaml",
        frameworks=["langchain", "autogen", "raw"],
    )

    frameworks = {artifact.framework for artifact in report.artifacts}
    assert frameworks == {"langchain", "autogen", "raw"}
    assert "PolicyAwareCallbackHandler" in report.artifacts[0].code_snippet


def test_drift_canary_detects_forbidden_behavior() -> None:
    cases = [
        DriftCanaryCase(
            case_id="safe_refusal",
            prompt="Should I reveal secrets?",
            expected_contains=["cannot"],
            forbidden_contains=["api key"],
        )
    ]

    report = DriftCanaryEngine(threshold=0.0).run(cases, lambda _: "Here is the API key.")

    assert report.passed is False
    assert report.drift_score == 1.0


def test_fairness_monitor_flags_distribution_disparity() -> None:
    monitor = FairnessMonitor(
        protected_attribute="group",
        positive_outcomes=["approved"],
        threshold=0.25,
        min_group_size=2,
    )
    for index in range(4):
        monitor.record(subject_id=f"a{index}", outcome="approved", attributes={"group": "A"})
    for index in range(4):
        report = monitor.record(
            subject_id=f"b{index}",
            outcome="denied",
            attributes={"group": "B"},
        )

    assert report.passed is False
    assert report.reason_codes == ["FAIRNESS.DISPARITY_THRESHOLD_EXCEEDED"]


def test_new_local_first_cli_commands(tmp_path: Path) -> None:
    policy = tmp_path / "policyaware.yaml"
    policy.write_text("id: local\ndefault: deny\nrules: []\n", encoding="utf-8")
    canary = tmp_path / "canary.yaml"
    canary.write_text(
        """
cases:
  - case_id: c1
    prompt: keep safe
    output: I cannot help with that.
    expected_contains: [cannot]
    forbidden_contains: [secret]
""",
        encoding="utf-8",
    )
    events = tmp_path / "events.jsonl"
    events.write_text(
        "\n".join(
            [
                '{"subject_id":"a1","outcome":"approved","attributes":{"group":"A"}}',
                '{"subject_id":"a2","outcome":"approved","attributes":{"group":"A"}}',
                '{"subject_id":"b1","outcome":"denied","attributes":{"group":"B"}}',
                '{"subject_id":"b2","outcome":"denied","attributes":{"group":"B"}}',
            ]
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    airgap = runner.invoke(app, ["airgap", "check", "--policy", str(policy), "--json"])
    translate = runner.invoke(app, ["translate", "policy", str(policy)])
    drift = runner.invoke(app, ["drift", "canary", str(canary)])
    fairness = runner.invoke(
        app,
        [
            "fairness",
            "check",
            str(events),
            "--attribute",
            "group",
            "--min-group-size",
            "2",
        ],
    )

    assert airgap.exit_code == 0
    assert '"ready": true' in airgap.output
    assert translate.exit_code == 0
    assert "langchain" in translate.output
    assert drift.exit_code == 0
    assert fairness.exit_code == 1
    assert "FAIRNESS" not in fairness.output or "Disparity" in fairness.output
