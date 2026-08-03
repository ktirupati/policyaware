from __future__ import annotations

from policyaware.integrations.haystack import PolicyAwareInputComponent, PolicyAwareOutputComponent


def main() -> None:
    input_guard = PolicyAwareInputComponent(
        config="policyaware.yaml",
        tenant="acme",
        user={"id": "u_123", "role": "analyst"},
        context={"region": "us", "risk": "low", "task_type": "rag_query"},
    )
    output_guard = PolicyAwareOutputComponent(
        config="policyaware.yaml",
        tenant="acme",
        user={"id": "u_123", "role": "analyst"},
        context={
            "region": "us",
            "risk": "low",
            "task_type": "rag_answer",
            "require_citations": True,
        },
    )

    query_result = input_guard.run(query="Summarize the policy for jane@example.com.")
    print(f"input_decision={query_result['decision']}")
    print(f"governed_query={query_result['query']}")

    # In a real Haystack pipeline, the governed query would continue to a retriever,
    # prompt builder, and generator. The answer below simulates that generator output.
    answer = "The support policy allows account summaries when PII is redacted [policy-doc-1]."
    output_result = output_guard.run(query=query_result["query"], answer=answer)
    print(f"output_allowed={output_result['allowed']}")
    print(f"output_decision={output_result['decision']}")
    print(f"evals={[check['name'] for check in output_result['policyaware']['evals']]}")


if __name__ == "__main__":
    main()
