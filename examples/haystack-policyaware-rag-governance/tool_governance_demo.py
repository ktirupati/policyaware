from __future__ import annotations

from policyaware.integrations.haystack import PolicyAwareToolGovernanceComponent


def main() -> None:
    tool_guard = PolicyAwareToolGovernanceComponent(
        tool_policy="tool-governance.yaml",
        agent_id="haystack_agent",
        tenant="acme",
        user={"id": "u_456", "role": "developer"},
        context={"region": "us", "risk": "medium", "task_type": "agent_tool_call"},
    )

    read_result = tool_guard.run(
        connector_id="github",
        action="read_file",
        arguments={"repo": "ktirupati/policyaware", "path": "README.md"},
    )
    print(f"read_file_decision={read_result['decision']}")

    create_pr_result = tool_guard.run(
        connector_id="github",
        action="create_pr",
        arguments={"repo": "ktirupati/policyaware", "title": "Update docs"},
    )
    print(f"create_pr_decision={create_pr_result['decision']}")
    print(f"create_pr_approval_required={create_pr_result['approval_required']}")

    delete_result = tool_guard.run(
        connector_id="github",
        action="delete_branch",
        arguments={"repo": "ktirupati/policyaware", "branch": "main"},
    )
    print(f"delete_branch_decision={delete_result['decision']}")


if __name__ == "__main__":
    main()
