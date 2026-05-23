from __future__ import annotations

from pathlib import Path

from policyaware import AuditLogger, Gateway, GatewayRequest, TraceViewer


base = Path(__file__).parent / ".policyaware-demo"
trace_file = base / "traces.jsonl"
if trace_file.exists():
    trace_file.unlink()

gateway = Gateway.from_policy_file(Path(__file__).with_name("policy.yaml"))
gateway.audit_logger = AuditLogger(trace_file)

prompts = [
    "Summarize claim ACME-42.",
    "Email jane@example.com about claim ACME-42.",
]

decisions = []
for prompt in prompts:
    response = gateway.chat(
        GatewayRequest(
            tenant="acme",
            app="audit-trace-viewer",
            user={"id": "support_1", "role": "support_agent"},
            context={"region": "us", "task_type": "support_summary", "risk": "low"},
            messages=[{"role": "user", "content": prompt}],
        )
    )
    decisions.append(response.policy.decision.value)

traces = gateway.audit_logger.read_traces()
viewer = TraceViewer().write_html(traces, base / "trace-viewer.html")

print(f"traces_written={len(traces)}")
print(f"viewer={viewer.relative_to(Path(__file__).parent).as_posix()}")
print(f"first_decision={decisions[0]}")
print(f"second_decision={decisions[1]}")
