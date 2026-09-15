from __future__ import annotations

from pathlib import Path

from policyaware import MCPPolicyProxy


POLICY = Path(__file__).parents[1] / "policies" / "tool-governance.yaml"


proxy = MCPPolicyProxy.from_policy_file(
    POLICY,
    agent_id="claude_desktop",
    user={"id": "u_123", "role": "developer"},
)


def show(label: str, request: dict[str, object]) -> None:
    result = proxy.evaluate(request)
    decision = result.decision.decision.value if result.decision else "pass_through"
    print(
        f"{label}: allowed={result.allowed} action={result.action} "
        f"decision={decision} redactions={result.redactions}"
    )
    if result.allowed and result.request:
        arguments = result.request.get("params", {}).get("arguments", {})
        if arguments:
            print(f"  forwarded_arguments={arguments}")
    if not result.allowed and result.response:
        error = result.response["error"]
        print(f"  jsonrpc_error={error['code']} {error['message']}")


show(
    "SAFE READ",
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "github.read_file", "arguments": {"path": "README.md"}},
    },
)
show(
    "PII READ",
    {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "github.read_file",
            "arguments": {"path": "case.txt", "query": "email jane@example.com"},
        },
    },
)
show(
    "CREATE PR",
    {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "github.create_pr", "arguments": {"branch": "policy-update"}},
    },
)
show(
    "DELETE BRANCH",
    {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "github.delete_branch", "arguments": {"branch": "main"}},
    },
)
show(
    "MEDICAL QUERY",
    {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "snowflake.query",
            "arguments": {"database": "medical", "sql": "select * from patient_claims"},
        },
    },
)

