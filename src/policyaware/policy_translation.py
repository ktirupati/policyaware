from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field


FrameworkName = Literal["langchain", "llamaindex", "autogen", "crewai", "openai", "anthropic", "raw"]


class PolicyTranslationArtifact(BaseModel):
    framework: str
    install_extra: str | None = None
    entrypoint: str
    generated_config: dict[str, Any] = Field(default_factory=dict)
    code_snippet: str
    notes: list[str] = Field(default_factory=list)


class PolicyTranslationReport(BaseModel):
    policy_id: str
    frameworks: list[str]
    artifacts: list[PolicyTranslationArtifact]


class PolicyTranslationEngine:
    """Translate one PolicyAware policy into framework-specific adapter recipes."""

    def translate_file(
        self,
        policy_file: str | Path,
        frameworks: list[FrameworkName] | None = None,
    ) -> PolicyTranslationReport:
        policy_path = Path(policy_file)
        policy = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
        return self.translate(policy, policy_file=str(policy_path), frameworks=frameworks)

    def translate(
        self,
        policy: dict[str, Any],
        *,
        policy_file: str = "policyaware.yaml",
        frameworks: list[FrameworkName] | None = None,
    ) -> PolicyTranslationReport:
        selected = frameworks or ["langchain", "llamaindex", "autogen", "crewai", "raw"]
        artifacts = [self._artifact(name, policy_file) for name in selected]
        return PolicyTranslationReport(
            policy_id=str(policy.get("id", "policyaware_policy")),
            frameworks=list(selected),
            artifacts=artifacts,
        )

    def _artifact(self, framework: FrameworkName, policy_file: str) -> PolicyTranslationArtifact:
        snippets: dict[str, tuple[str | None, str, str]] = {
            "langchain": (
                None,
                "PolicyAwareCallbackHandler",
                (
                    "from policyaware.integrations.langchain import PolicyAwareCallbackHandler\n\n"
                    f"callbacks = [PolicyAwareCallbackHandler(config={policy_file!r})]\n"
                    "# pass callbacks=callbacks into your LangChain runnable/model call"
                ),
            ),
            "llamaindex": (
                None,
                "PolicyAwareCallbackHandler",
                (
                    "from policyaware.integrations.llamaindex import PolicyAwareCallbackHandler\n\n"
                    f"callback = PolicyAwareCallbackHandler(config={policy_file!r})\n"
                    "# attach callback to your LlamaIndex query/retrieval flow"
                ),
            ),
            "autogen": (
                None,
                "Gateway",
                (
                    "from policyaware import Gateway, GatewayRequest\n\n"
                    f"gateway = Gateway.from_policy_file({policy_file!r})\n"
                    "# evaluate AutoGen agent messages before tool/model execution"
                ),
            ),
            "crewai": (
                None,
                "ToolPolicyEngine",
                (
                    "from policyaware import ToolCallRequest, ToolPolicyEngine\n\n"
                    f"tools = ToolPolicyEngine.from_file({policy_file!r})\n"
                    "# check CrewAI tool invocations before running each tool"
                ),
            ),
            "openai": (
                None,
                "Gateway",
                (
                    "from policyaware import Gateway, GatewayRequest\n\n"
                    f"gateway = Gateway.from_policy_file({policy_file!r})\n"
                    "# run gateway.chat(...) before calling OpenAI-compatible endpoints"
                ),
            ),
            "anthropic": (
                None,
                "Gateway",
                (
                    "from policyaware import Gateway, GatewayRequest\n\n"
                    f"gateway = Gateway.from_policy_file({policy_file!r})\n"
                    "# run gateway.chat(...) before calling Anthropic messages APIs"
                ),
            ),
            "raw": (
                None,
                "PolicyEngine",
                (
                    "from policyaware import DataProtectionEngine, GatewayRequest, PolicyEngine\n\n"
                    f"engine = PolicyEngine.from_file({policy_file!r})\n"
                    "findings = DataProtectionEngine().inspect(prompt)\n"
                    "decision = engine.decide(GatewayRequest(tenant='default', app='raw', messages=[{'role': 'user', 'content': prompt}]), findings)"
                ),
            ),
        }
        install_extra, entrypoint, code = snippets[framework]
        return PolicyTranslationArtifact(
            framework=framework,
            install_extra=install_extra,
            entrypoint=entrypoint,
            generated_config={"policy_file": policy_file, "deny_by_default": True},
            code_snippet=code,
            notes=[
                "Generated artifact is an adapter recipe; PolicyAware remains the source of truth.",
                "Review framework lifecycle hooks before production rollout.",
            ],
        )
