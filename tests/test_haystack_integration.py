from __future__ import annotations

from policyaware.integrations.haystack import (
    PolicyAwareInputComponent,
    PolicyAwareOutputComponent,
    PolicyAwareToolGovernanceComponent,
)


POLICY_YAML = """
id: haystack_policy
default: deny
rules:
  - name: block_secrets
    effect: deny
    when:
      data.contains_secrets: true
  - name: allow_haystack_users
    effect: allow
    when:
      user.role_in: ["developer", "analyst"]
      request.region: "us"
      request.risk_in: ["low", "medium"]
  - name: redact_pii
    effect: transform
    action: redact
    when:
      data.contains_pii: true
"""


TOOL_POLICY_YAML = """
default: deny
connectors:
  - id: github
    actions:
      read_file:
        effect: allow
        when:
          user.role_in: ["developer"]
      create_pr:
        effect: require_approval
        when:
          user.role_in: ["developer"]
"""


def _policy_file(tmp_path):
    path = tmp_path / "policyaware.yaml"
    path.write_text(POLICY_YAML, encoding="utf-8")
    return path


def _tool_policy_file(tmp_path):
    path = tmp_path / "tool-governance.yaml"
    path.write_text(TOOL_POLICY_YAML, encoding="utf-8")
    return path


def test_haystack_input_component_allows_and_redacts_pii(tmp_path):
    component = PolicyAwareInputComponent(config=_policy_file(tmp_path))

    result = component.run(query="Email jane@example.com with a safe RAG summary.")

    assert result["allowed"] is True
    assert result["decision"] == "conditional_allow"
    assert "[REDACTED_EMAIL]" in result["query"]
    assert result["policyaware"]["metadata"]["input_findings"]["contains_pii"] is True


def test_haystack_input_component_denies_secret(tmp_path):
    component = PolicyAwareInputComponent(config=_policy_file(tmp_path))

    result = component.run(query="Use secret_api_key_abcdefghijklmnop in the prompt.")

    assert result["allowed"] is False
    assert result["decision"] == "deny"
    assert result["query"] == ""


def test_haystack_output_component_reports_missing_citation(tmp_path):
    component = PolicyAwareOutputComponent(config=_policy_file(tmp_path))

    result = component.run(query="Answer with citations.", answer="Answer without citation")

    assert result["decision"] == "allow"
    citation = next(check for check in result["policyaware"]["evals"] if check["name"] == "citation_required")
    assert citation["passed"] is False


def test_haystack_tool_governance_component_allows_and_requires_approval(tmp_path):
    component = PolicyAwareToolGovernanceComponent(tool_policy=_tool_policy_file(tmp_path))

    read_result = component.run(connector_id="github", action="read_file", arguments={"path": "README.md"})
    write_result = component.run(connector_id="github", action="create_pr", arguments={"title": "Update docs"})

    assert read_result["allowed"] is True
    assert read_result["decision"] == "allow"
    assert write_result["allowed"] is False
    assert write_result["approval_required"] is True
    assert write_result["decision"] == "require_approval"
