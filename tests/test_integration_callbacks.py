from __future__ import annotations

import asyncio

from policyaware.integrations.langchain import PolicyAwareCallbackHandler as LangChainPolicyAwareCallback
from policyaware.integrations.llamaindex import PolicyAwareCallbackHandler as LlamaIndexPolicyAwareCallback


POLICY_YAML = """
id: callback_policy
default: deny
rules:
  - name: block_secrets
    effect: deny
    when:
      data.contains_secrets: true
  - name: allow_enterprise_users
    effect: allow
    when:
      user.role_in: ["developer", "support_agent"]
      request.region: "us"
      request.risk_in: ["low", "medium"]
  - name: redact_pii
    effect: transform
    action: redact
    when:
      data.contains_pii: true
"""


def _policy_file(tmp_path):
    path = tmp_path / "policyaware.yaml"
    path.write_text(POLICY_YAML, encoding="utf-8")
    return path


def test_langchain_callback_aggregates_stream_and_scores_policy(tmp_path):
    handler = LangChainPolicyAwareCallback(config=_policy_file(tmp_path))

    handler.on_llm_start(prompts=["Email jane@example.com with the summary."])
    handler.on_llm_new_token("Safe ")
    handler.on_llm_new_token("answer")
    result = handler.on_llm_end()

    assert result.output_text == "Safe answer"
    assert result.input_findings.contains_pii is True
    assert result.output_findings.contains_sensitive is False
    assert result.input_tokens >= 1
    assert result.output_tokens >= 1
    assert result.policy_decision.decision.value == "conditional_allow"
    assert result.to_dict()["decision"] == "conditional_allow"


def test_langchain_callback_extracts_response_generations(tmp_path):
    class Generation:
        text = "Final answer with jane@example.com"

    class Response:
        generations = [[Generation()]]

    handler = LangChainPolicyAwareCallback(config=_policy_file(tmp_path))
    handler.on_llm_start(prompts=["Summarize public release notes."])
    result = handler.on_llm_end(Response())

    assert "Final answer" in result.output_text
    assert result.output_findings.contains_pii is True
    assert result.contains_output_sensitive_data is True


def test_langchain_callback_async_methods(tmp_path):
    async def run_callback():
        handler = LangChainPolicyAwareCallback(config=_policy_file(tmp_path))
        await handler.aon_llm_start(prompts=["Summarize the safe text."])
        await handler.aon_llm_new_token("Done")
        return await handler.aon_llm_end()

    result = asyncio.run(run_callback())

    assert result.output_text == "Done"
    assert result.policy_decision.decision.value == "allow"


def test_llamaindex_callback_payload_and_stream(tmp_path):
    handler = LlamaIndexPolicyAwareCallback(config=_policy_file(tmp_path))

    handler.on_event_start(payload={"query_str": "Answer with citations for the policy."})
    handler.on_llm_new_token("Grounded answer [doc-1]")
    result = handler.on_event_end(payload={})

    assert result.prompt_text == "Answer with citations for the policy."
    assert result.output_text == "Grounded answer [doc-1]"
    assert result.policy_decision.decision.value == "allow"
    assert all(check.passed for check in result.evals)


def test_llamaindex_callback_reports_missing_citation(tmp_path):
    handler = LlamaIndexPolicyAwareCallback(config=_policy_file(tmp_path))

    handler.on_event_start(payload={"query": "Answer this RAG question."})
    result = handler.on_event_end(payload={"response": "Answer without citation"})

    citation_check = next(check for check in result.evals if check.name == "citation_required")
    assert citation_check.passed is False
