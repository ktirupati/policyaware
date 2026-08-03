from __future__ import annotations

import re
import html
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class IntegrationRecommendation:
    """Explainable recommendation for a PolicyAware integration."""

    name: str
    score: int
    confidence: float
    install: str
    example: str
    docs: str
    reasons: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IntegrationRecommendationReport:
    """Recommendation report generated from project signals and user hints."""

    scanned_path: str
    signals: dict[str, Any]
    recommendations: list[IntegrationRecommendation]

    @property
    def best(self) -> IntegrationRecommendation | None:
        return self.recommendations[0] if self.recommendations else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned_path": self.scanned_path,
            "signals": self.signals,
            "recommendations": [item.to_dict() for item in self.recommendations],
        }

    def write_html(self, path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(_render_recommendation_html(self), encoding="utf-8")
        return output


class IntegrationRecommender:
    """Rules-based, explainable recommender for PolicyAware integrations."""

    DEFAULT_MAX_FILES = 300
    DEFAULT_MAX_BYTES_PER_FILE = 128 * 1024
    DEFAULT_EXTENSIONS = {
        ".py",
        ".txt",
        ".md",
        ".toml",
        ".yaml",
        ".yml",
        ".json",
        ".env",
        ".ini",
        ".properties",
        ".ipynb",
    }
    DEFAULT_EXCLUDED_DIRS = {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }

    def recommend(
        self,
        path: str | Path = ".",
        *,
        use_case: str | None = None,
        framework: str | None = None,
        needs: str | list[str] | None = None,
        max_files: int = DEFAULT_MAX_FILES,
    ) -> IntegrationRecommendationReport:
        root = Path(path).resolve()
        texts = _read_project_texts(root, max_files=max_files)
        combined = "\n".join(texts.values()).lower()
        hints = _normalize_hints(use_case=use_case, framework=framework, needs=needs)
        signals = self._detect_signals(root, texts, combined, hints)
        recommendations = self._score(signals)
        return IntegrationRecommendationReport(
            scanned_path=str(root),
            signals=signals,
            recommendations=recommendations,
        )

    def _detect_signals(
        self,
        root: Path,
        texts: dict[str, str],
        combined: str,
        hints: dict[str, Any],
    ) -> dict[str, Any]:
        filenames = {Path(name).name.lower() for name in texts}
        paths = {name.lower().replace("\\", "/") for name in texts}
        hint_text = " ".join(
            [
                str(hints.get("use_case") or ""),
                str(hints.get("framework") or ""),
                " ".join(hints.get("needs", [])),
            ]
        ).lower()
        all_text = f"{combined}\n{hint_text}"

        return {
            "hints": hints,
            "files_sampled": len(texts),
            "has_policyaware_policy": any(
                name in {"policyaware.yaml", "policyaware.yml"} or "policyaware" in name and name.endswith((".yaml", ".yml"))
                for name in filenames
            ),
            "has_tool_governance": any("tool-governance" in name for name in filenames),
            "has_fastapi": _contains_any(all_text, ["fastapi", "from fastapi import", "fastapi("]),
            "has_flask": _contains_any(all_text, ["from flask import", "flask("]),
            "has_langchain": _contains_any(all_text, ["langchain", "llmchain", "langchain_openai"]),
            "has_langgraph": _contains_any(all_text, ["langgraph", "stategraph", "toolnode"]),
            "has_llamaindex": _contains_any(all_text, ["llama_index", "llamaindex", "vectorstoreindex"]),
            "has_haystack": _contains_any(all_text, ["haystack", "documentstore", "pipeline()"]),
            "has_guardrails_ai": _contains_any(all_text, ["guardrails", "guardrails-ai", "guardrails_ai"]),
            "has_nemo_guardrails": _contains_any(all_text, ["nemoguardrails", "nemo guardrails", "rails.co"]),
            "has_rag": _contains_any(
                all_text,
                ["retriever", "vectorstore", "vector_store", "embedding", "rag", "citation", "grounding"],
            ),
            "has_agent": _contains_any(
                all_text,
                ["agent", "tool call", "tools=", "bind_tools", "autonomous", "planner", "executor"],
            ),
            "has_mcp": _contains_any(all_text, ["mcp", "model context protocol", "connector_id", "tool-governance"]),
            "has_pii_or_privacy_need": _contains_any(
                all_text,
                ["pii", "phi", "privacy", "redact", "hipaa", "patient", "ssn", "secret", "api_key"],
            ),
            "has_audit_need": _contains_any(
                all_text,
                ["audit", "compliance", "evidence", "trace", "otel", "opentelemetry", "prometheus"],
            ),
            "has_provider_need": _contains_any(
                all_text,
                ["azureopenai", "azure openai", "anthropic", "bedrock", "vertex", "ollama", "vllm"],
            ),
            "has_scan_need": _contains_any(all_text, ["scan", "sarif", "code scanning", "secret scanning"]),
            "has_pyproject": "pyproject.toml" in filenames,
            "has_requirements": "requirements.txt" in filenames,
            "looks_like_repo": root.is_dir() and (root / ".git").exists() or bool(texts),
            "matched_paths": sorted(path for path in paths if _interesting_path(path))[:20],
        }

    def _score(self, signals: dict[str, Any]) -> list[IntegrationRecommendation]:
        candidates = [
            _candidate(
                "FastAPI middleware",
                "pip install policyaware",
                "examples/fastapi-llm-policy-middleware",
                "docs/working-examples.md",
                [
                    (signals["has_fastapi"], 55, "Detected FastAPI project patterns."),
                    (signals["hints"]["use_case"] in {"api", "api_service", "service"}, 25, "User hint says this is an API/service."),
                    (not signals["has_policyaware_policy"], 10, "No PolicyAware policy file detected yet."),
                ],
                ["Add PolicyAware middleware before provider calls.", "Run `policyaware init` and validate the generated policy."],
            ),
            _candidate(
                "LangChain policy guardrails",
                "pip install policyaware",
                "examples/langchain-policy-guardrails",
                "docs/capabilities/integration-callbacks.md",
                [
                    (signals["has_langchain"], 60, "Detected LangChain imports or chain patterns."),
                    (signals["hints"]["framework"] == "langchain", 30, "User selected LangChain."),
                    (signals["has_rag"], 10, "Detected RAG/retriever patterns."),
                ],
                ["Add `PolicyAwareCallbackHandler` to callbacks.", "Review output leakage and eval results after chain completion."],
            ),
            _candidate(
                "LangGraph agent node guard",
                "pip install policyaware",
                "examples/langgraph-agent-governance",
                "docs/capabilities/langgraph-integration.md",
                [
                    (signals["has_langgraph"], 70, "Detected LangGraph StateGraph/ToolNode patterns."),
                    (signals["hints"]["framework"] == "langgraph", 30, "User selected LangGraph."),
                    (signals["has_agent"], 15, "Detected agent/tool execution patterns."),
                    (not signals["has_tool_governance"], 10, "No tool-governance policy detected yet."),
                ],
                ["Wrap graph nodes with `PolicyAwareNodeGuard`.", "Add `tool-governance.yaml` before tool execution."],
            ),
            _candidate(
                "Haystack RAG governance",
                'pip install "policyaware[haystack]"',
                "examples/haystack-policyaware-rag-governance",
                "docs/capabilities/haystack-integration.md",
                [
                    (signals["has_haystack"], 65, "Detected Haystack imports or pipeline patterns."),
                    (signals["hints"]["framework"] == "haystack", 30, "User selected Haystack."),
                    (signals["has_rag"], 20, "Detected RAG, embedding, retriever, citation, or grounding patterns."),
                ],
                ["Add input and output PolicyAware components to the pipeline.", "Enable citation and sensitive-output checks."],
            ),
            _candidate(
                "LlamaIndex callback governance",
                "pip install policyaware",
                "docs/capabilities/integration-callbacks.md",
                "docs/capabilities/integration-callbacks.md",
                [
                    (signals["has_llamaindex"], 65, "Detected LlamaIndex imports or index patterns."),
                    (signals["hints"]["framework"] in {"llamaindex", "llama_index"}, 30, "User selected LlamaIndex."),
                    (signals["has_rag"], 20, "Detected RAG/retrieval patterns."),
                ],
                ["Add the PolicyAware callback handler.", "Track citation, grounding, output leakage, and token counts."],
            ),
            _candidate(
                "MCP/tool permission gateway",
                "pip install policyaware",
                "examples/mcp-tool-permission-gateway",
                "docs/capabilities/tool-governance.md",
                [
                    (signals["has_mcp"], 50, "Detected MCP/tool governance terms or connector/action patterns."),
                    (signals["has_agent"], 25, "Detected agent/tool execution patterns."),
                    (signals["hints"]["use_case"] in {"agent", "tool", "mcp"}, 30, "User hint points to agent/tool governance."),
                    (not signals["has_tool_governance"], 10, "No tool-governance policy detected yet."),
                ],
                ["Create `tool-governance.yaml`.", "Check every connector/action with `ToolPolicyEngine` before execution."],
            ),
            _candidate(
                "Privacy detection and redaction",
                'pip install "policyaware[privacy]"',
                "examples/pii-redaction-policy",
                "docs/capabilities/data-protection.md",
                [
                    (signals["has_pii_or_privacy_need"], 60, "Detected PII/PHI/privacy/security terms."),
                    ("privacy" in signals["hints"]["needs"], 25, "User listed privacy as a need."),
                    ("pii" in signals["hints"]["needs"], 25, "User listed PII as a need."),
                ],
                ["Start with `DataProtectionEngine.inspect(...)`.", "Use `policyaware[privacy]` for Presidio-backed detection when needed."],
            ),
            _candidate(
                "Guardrails orchestration",
                'pip install "policyaware[guardrails]"',
                "examples/full-stack-guardrails",
                "docs/capabilities/guardrails-integrations.md",
                [
                    (signals["has_guardrails_ai"], 35, "Detected Guardrails AI usage or intent."),
                    (signals["has_nemo_guardrails"], 35, "Detected NeMo Guardrails usage or intent."),
                    ("guardrails" in signals["hints"]["needs"], 30, "User listed guardrails as a need."),
                ],
                ["Keep Guardrails AI/NeMo optional.", "Run them as input/output validators inside PolicyAware Gateway."],
            ),
            _candidate(
                "Audit and AGT-style evidence",
                "pip install policyaware",
                "examples/microsoft-agt-interop",
                "docs/capabilities/microsoft-agt-interop.md",
                [
                    (signals["has_audit_need"], 55, "Detected audit/compliance/evidence/trace needs."),
                    ("audit" in signals["hints"]["needs"], 25, "User listed audit as a need."),
                    ("compliance" in signals["hints"]["needs"], 25, "User listed compliance as a need."),
                ],
                ["Enable audit traces.", "Export decisions with `to_agt_gateway_evidence` or `to_agt_tool_evidence`."],
            ),
            _candidate(
                "Provider routing",
                'pip install "policyaware[providers]"',
                "docs/provider-adapter-examples.md",
                "docs/capabilities/model-routing-providers.md",
                [
                    (signals["has_provider_need"], 50, "Detected provider platform names."),
                    ("routing" in signals["hints"]["needs"], 25, "User listed routing as a need."),
                    ("cost" in signals["hints"]["needs"], 20, "User listed cost control as a need."),
                ],
                ["Configure provider adapters.", "Route by risk, region, cost, latency, and policy."],
            ),
            _candidate(
                "Local code governance scan",
                "pip install policyaware",
                "docs/local-code-scan.md",
                "docs/local-code-scan.md",
                [
                    (signals["has_scan_need"], 45, "Detected scan/SARIF/code-scanning terms."),
                    (signals["hints"]["use_case"] in {"scan", "scanner", "code_scan"}, 35, "User hint points to local code scanning."),
                    (signals["looks_like_repo"], 10, "The target looks like a source repository."),
                ],
                ["Run `policyaware scan . --format html,json,sarif,markdown`.", "Use SARIF in CI for pull-request governance."],
            ),
        ]
        ranked = sorted((item for item in candidates if item.score > 0), key=lambda item: item.score, reverse=True)
        if not ranked:
            ranked = [
                IntegrationRecommendation(
                    name="Gateway orchestration",
                    score=40,
                    confidence=0.4,
                    install="pip install policyaware",
                    example="docs/working-examples.md",
                    docs="docs/capabilities/gateway-orchestration.md",
                    reasons=["No strong framework signal detected; start with the vendor-neutral Gateway API."],
                    next_steps=[
                        "Run `policyaware init`.",
                        "Send one request through `Gateway.chat(...)`.",
                        "Run `policyaware scan .` before production.",
                    ],
                )
            ]
        return ranked[:5]


def _candidate(
    name: str,
    install: str,
    example: str,
    docs: str,
    weighted_reasons: list[tuple[bool, int, str]],
    next_steps: list[str],
) -> IntegrationRecommendation:
    score = sum(weight for matched, weight, _ in weighted_reasons if matched)
    reasons = [reason for matched, _, reason in weighted_reasons if matched]
    return IntegrationRecommendation(
        name=name,
        score=score,
        confidence=round(min(score, 100) / 100, 2),
        install=install,
        example=example,
        docs=docs,
        reasons=reasons,
        next_steps=next_steps,
    )


def _read_project_texts(root: Path, *, max_files: int) -> dict[str, str]:
    files = [root] if root.is_file() else list(_iter_project_files(root, max_files=max_files))
    texts: dict[str, str] = {}
    for path in files[:max_files]:
        try:
            if path.stat().st_size > IntegrationRecommender.DEFAULT_MAX_BYTES_PER_FILE:
                continue
            relative = str(path.relative_to(root if root.is_dir() else root.parent))
            texts[relative] = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
    return texts


def _iter_project_files(root: Path, *, max_files: int) -> list[Path]:
    if not root.exists():
        return []
    files: list[Path] = []
    for path in root.rglob("*"):
        if len(files) >= max_files:
            break
        if not path.is_file():
            continue
        if any(part in IntegrationRecommender.DEFAULT_EXCLUDED_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in IntegrationRecommender.DEFAULT_EXTENSIONS:
            continue
        files.append(path)
    return files


def _normalize_hints(
    *,
    use_case: str | None,
    framework: str | None,
    needs: str | list[str] | None,
) -> dict[str, Any]:
    needs_list = []
    if isinstance(needs, str):
        needs_list = [item for item in re.split(r"[\s,;]+", needs.lower()) if item]
    elif needs:
        needs_list = [str(item).strip().lower() for item in needs if str(item).strip()]
    return {
        "use_case": (use_case or "").strip().lower().replace("-", "_"),
        "framework": (framework or "").strip().lower().replace("-", "_"),
        "needs": needs_list,
    }


def _contains_any(text: str, needles: list[str]) -> bool:
    return any(needle.lower() in text for needle in needles)


def _interesting_path(path: str) -> bool:
    names = (
        "requirements",
        "pyproject",
        "policyaware",
        "tool-governance",
        "chain",
        "graph",
        "agent",
        "rag",
        "app.py",
        "main.py",
    )
    return any(name in path for name in names)


def _render_recommendation_html(report: IntegrationRecommendationReport) -> str:
    best = report.best
    rows = "\n".join(
        f"""
        <tr>
          <td>{index}</td>
          <td><strong>{html.escape(item.name)}</strong></td>
          <td>{item.confidence:.2f}</td>
          <td>{html.escape('; '.join(item.reasons) or 'Default recommendation.')}</td>
          <td><code>{html.escape(item.install)}</code></td>
          <td><code>{html.escape(item.example)}</code></td>
        </tr>
        """
        for index, item in enumerate(report.recommendations, start=1)
    )
    signal_items = "\n".join(
        f"<li><strong>{html.escape(str(key))}</strong>: {html.escape(str(value))}</li>"
        for key, value in report.signals.items()
        if key not in {"hints"}
    )
    next_steps = ""
    if best:
        next_steps = "\n".join(f"<li>{html.escape(step)}</li>" for step in best.next_steps)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PolicyAware Integration Recommendation Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; color: #172033; background: #f6f8fb; }}
    header {{ background: #10243e; color: white; padding: 28px 36px; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 28px; }}
    section {{ background: white; border: 1px solid #dde5ef; border-radius: 8px; padding: 22px; margin: 18px 0; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; border-bottom: 1px solid #e7edf4; padding: 10px; vertical-align: top; }}
    th {{ background: #f0f4f8; }}
    code {{ background: #edf2f7; padding: 2px 5px; border-radius: 4px; }}
    .best {{ border-left: 6px solid #1668dc; }}
    .muted {{ color: #5d6b7a; }}
  </style>
</head>
<body>
  <header>
    <h1>PolicyAware Integration Recommendation Report</h1>
    <p>Explainable, local recommendations from project signals and user hints.</p>
  </header>
  <main>
    <section class="best">
      <h2>Best Recommendation</h2>
      <p><strong>{html.escape(best.name if best else 'Gateway orchestration')}</strong></p>
      <p class="muted">Scanned path: {html.escape(report.scanned_path)}</p>
      <p>Confidence: {best.confidence if best else 0:.2f}</p>
      <p>Install: <code>{html.escape(best.install if best else 'pip install policyaware')}</code></p>
      <p>Example: <code>{html.escape(best.example if best else 'docs/working-examples.md')}</code></p>
      <h3>Next Steps</h3>
      <ol>{next_steps}</ol>
    </section>
    <section>
      <h2>Ranked Recommendations</h2>
      <table>
        <thead>
          <tr><th>Rank</th><th>Integration</th><th>Confidence</th><th>Why</th><th>Install</th><th>Example</th></tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Detected Signals</h2>
      <ul>{signal_items}</ul>
    </section>
  </main>
</body>
</html>
"""
