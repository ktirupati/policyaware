from __future__ import annotations

from pathlib import Path

from policyaware import Gateway, GatewayRequest, RuntimeEvaluator


gateway = Gateway.from_policy_file(Path(__file__).with_name("policy.yaml"))
evaluator = RuntimeEvaluator()


def run_case(name: str, prompt: str, answer: str) -> None:
    request = GatewayRequest(
        tenant="hospital-a",
        app="regulated-rag-assistant",
        user={"id": "clinician_1", "role": "clinician"},
        context={
            "region": "us",
            "domain": "healthcare",
            "task_type": "rag_answer",
            "risk": "low",
            "require_citations": True,
        },
        messages=[{"role": "user", "content": prompt}],
    )
    response = gateway.chat(request)
    evals = evaluator.evaluate(request, answer, response.policy)
    citation = next(result for result in evals if result.name == "citation_required")
    actions = f" actions={','.join(response.policy.actions)}" if response.policy.actions else ""
    print(
        f"{name} decision={response.policy.decision.value} "
        f"citation_check={citation.passed}{actions} risk={response.risk.tier.value}"
    )


run_case(
    "grounded_answer",
    "What does the discharge policy say?",
    "Patients receive discharge instructions before leaving [1].",
)
run_case(
    "missing_citation",
    "What does the discharge policy say?",
    "Patients receive discharge instructions before leaving.",
)
run_case(
    "phi_request",
    "Patient id ABCDE diagnosis: diabetes. Summarize follow-up guidance.",
    "Follow-up guidance is documented in the care plan [2].",
)

