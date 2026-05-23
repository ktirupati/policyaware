from __future__ import annotations

from pathlib import Path

from policyaware import ToolPolicyEngine
from policyaware.models import ToolCallRequest


engine = ToolPolicyEngine.from_file(Path(__file__).with_name("tool-governance.yaml"))


def decide(
    label: str,
    connector: str,
    action: str,
    role: str,
    arguments: dict[str, object] | None = None,
) -> None:
    decision = engine.decide(
        ToolCallRequest(
            agent_id="research_agent",
            connector_id=connector,
            action=action,
            user={"id": "user_1", "role": role},
            arguments=arguments or {},
        )
    )
    print(
        f"{label}: {decision.decision.value} "
        f"approval_required={decision.approval_required}"
    )


decide("github.read_file as developer", "github", "read_file", "developer")
decide("github.create_pr as developer", "github", "create_pr", "developer")
decide("github.delete_branch as developer", "github", "delete_branch", "developer")
decide(
    "snowflake.query medical database",
    "snowflake",
    "query",
    "analyst",
    {"database": "medical", "sql": "select * from patient_claims"},
)

