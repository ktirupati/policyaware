from __future__ import annotations

import json
from pathlib import Path

from policyaware import Gateway, GatewayRequest
from policyaware.approvals import FileApprovalClient


base = Path(__file__).parent / ".policyaware-demo"
approval_file = base / "approvals.jsonl"
if approval_file.exists():
    approval_file.unlink()

gateway = Gateway.from_policy_file(Path(__file__).with_name("policy.yaml"))
gateway.approval_client = FileApprovalClient(approval_file)

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="approval-workflow-hooks",
        user={"id": "support_1", "role": "support_agent"},
        context={
            "region": "us",
            "task_type": "customer_refund",
            "business_impact": "critical",
            "action_type": "purchase",
        },
        messages=[{"role": "user", "content": "Refund this customer immediately."}],
    )
)

approval = json.loads(approval_file.read_text(encoding="utf-8").splitlines()[0])

print(f"decision={response.policy.decision.value}")
print(f"model_called={bool(response.route)}")
print(f"approval_file={approval_file.relative_to(Path(__file__).parent).as_posix()}")
print(f"approval_status={approval['status']}")
