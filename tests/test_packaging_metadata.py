from pathlib import Path
import tomllib


def _project_metadata() -> dict:
    return tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))


def test_base_dependencies_remain_lightweight() -> None:
    dependencies = set(_project_metadata()["project"]["dependencies"])

    assert dependencies == {
        "pydantic>=2.6",
        "PyYAML>=6.0",
        "typer>=0.12",
        "rich>=13.7",
    }


def test_user_friendly_optional_dependency_groups_exist() -> None:
    extras = _project_metadata()["project"]["optional-dependencies"]

    assert "privacy" in extras
    assert "guardrails" in extras
    assert "all" in extras
    assert "presidio-analyzer>=2.2" in extras["privacy"]
    assert "presidio-anonymizer>=2.2" in extras["privacy"]
    assert "spacy>=3.7" in extras["privacy"]
    assert "nemoguardrails>=0.10" in extras["guardrails"]
    assert "guardrails-ai>=0.5" in extras["guardrails"]


def test_backward_compatible_optional_dependency_aliases_remain() -> None:
    extras = _project_metadata()["project"]["optional-dependencies"]

    for alias in ("presidio", "nemo", "guardrails-ai", "full", "all-ml"):
        assert alias in extras
