from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from policyaware import IntegrationRecommender
from policyaware.cli import app


def test_recommender_detects_langgraph_agent(tmp_path: Path) -> None:
    (tmp_path / "graph.py").write_text(
        """
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode

graph = StateGraph(dict)
tools = ToolNode([])
""",
        encoding="utf-8",
    )

    report = IntegrationRecommender().recommend(tmp_path)

    assert report.best is not None
    assert report.best.name == "LangGraph agent node guard"
    assert "Detected LangGraph" in " ".join(report.best.reasons)


def test_recommender_uses_hints_without_framework_files(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("Building a compliant support assistant.", encoding="utf-8")

    report = IntegrationRecommender().recommend(
        tmp_path,
        use_case="rag",
        framework="haystack",
        needs="citations pii audit",
    )
    names = [item.name for item in report.recommendations]

    assert names[0] == "Haystack RAG governance"
    assert "Privacy detection and redaction" in names
    assert "Audit and AGT-style evidence" in names


def test_recommender_detects_fastapi_and_privacy(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
from fastapi import FastAPI

app = FastAPI()
prompt = "patient SSN and email should be redacted"
""",
        encoding="utf-8",
    )

    report = IntegrationRecommender().recommend(tmp_path)
    names = [item.name for item in report.recommendations]

    assert names[0] == "FastAPI middleware"
    assert "Privacy detection and redaction" in names


def test_integrations_recommend_cli_json(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\nagent = AgentExecutor\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["integrations", "recommend", str(tmp_path), "--json"])

    assert result.exit_code == 0
    assert '"recommendations"' in result.output
    assert '"LangChain policy guardrails"' in result.output


def test_integrations_recommend_cli_human_output(tmp_path: Path) -> None:
    (tmp_path / "graph.py").write_text("from langgraph.graph import StateGraph\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["integrations", "recommend", str(tmp_path)])

    assert result.exit_code == 0
    assert "PolicyAware Integration Recommender" in result.output
    assert "LangGraph" in result.output
