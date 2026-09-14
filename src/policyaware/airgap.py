from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


REMOTE_PREFIXES = ("http://", "https://", "s3://", "gs://", "abfs://", "adl://", "az://")


class AirGapFinding(BaseModel):
    passed: bool
    severity: str = "info"
    code: str
    message: str
    recommendation: str | None = None


class AirGapReadinessReport(BaseModel):
    ready: bool
    mode: str = "air_gapped"
    findings: list[AirGapFinding] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


class AirGapReadinessChecker:
    """Validate that a PolicyAware deployment can run without cloud callbacks."""

    def check(
        self,
        *,
        policy_sources: list[str | Path] | None = None,
        model_sources: list[str] | None = None,
        allow_remote_policy_sources: bool = False,
        require_local_models: bool = True,
        require_local_audit_storage: bool = True,
        audit_path: str | Path | None = ".policyaware/audit.db",
    ) -> AirGapReadinessReport:
        findings: list[AirGapFinding] = []
        policy_sources = policy_sources or ["policyaware.yaml"]
        model_sources = model_sources or ["local"]

        for source in policy_sources:
            source_text = str(source)
            is_remote = source_text.startswith(REMOTE_PREFIXES)
            if is_remote and not allow_remote_policy_sources:
                findings.append(
                    AirGapFinding(
                        passed=False,
                        severity="critical",
                        code="AIRGAP.REMOTE_POLICY_SOURCE",
                        message=f"Remote policy source is not air-gap safe: {source_text}",
                        recommendation="Use a local signed policy bundle or pre-synced mounted volume.",
                    )
                )
            elif not is_remote and not Path(source_text).exists():
                findings.append(
                    AirGapFinding(
                        passed=False,
                        severity="high",
                        code="AIRGAP.LOCAL_POLICY_MISSING",
                        message=f"Local policy file was not found: {source_text}",
                        recommendation="Package the policy file into the container image or mount it read-only.",
                    )
                )
            else:
                findings.append(
                    AirGapFinding(
                        passed=True,
                        code="AIRGAP.POLICY_SOURCE_OK",
                        message=f"Policy source is air-gap compatible: {source_text}",
                    )
                )

        remote_models = [
            source
            for source in model_sources
            if source.startswith(REMOTE_PREFIXES) or source.lower() in {"openai", "anthropic", "bedrock", "vertex"}
        ]
        if require_local_models and remote_models:
            findings.append(
                AirGapFinding(
                    passed=False,
                    severity="critical",
                    code="AIRGAP.REMOTE_MODEL_SOURCE",
                    message=f"Remote model source configured: {', '.join(remote_models)}",
                    recommendation="Use a local model runtime such as Ollama, vLLM, llama.cpp, or an on-prem provider.",
                )
            )
        else:
            findings.append(
                AirGapFinding(
                    passed=True,
                    code="AIRGAP.MODEL_SOURCE_OK",
                    message="Model source configuration is compatible with local or on-prem execution.",
                )
            )

        if require_local_audit_storage:
            audit = Path(audit_path or ".policyaware/audit.db")
            if str(audit).startswith(REMOTE_PREFIXES):
                findings.append(
                    AirGapFinding(
                        passed=False,
                        severity="high",
                        code="AIRGAP.REMOTE_AUDIT_STORAGE",
                        message="Audit storage points to a remote location.",
                        recommendation="Use local SQLite or append-only local JSONL, then export through approved channels.",
                    )
                )
            else:
                findings.append(
                    AirGapFinding(
                        passed=True,
                        code="AIRGAP.AUDIT_STORAGE_OK",
                        message="Audit storage is local-path compatible.",
                    )
                )

        ready = all(finding.passed for finding in findings)
        return AirGapReadinessReport(
            ready=ready,
            findings=findings,
            summary={
                "policy_sources": [str(source) for source in policy_sources],
                "model_sources": model_sources,
                "audit_path": str(audit_path),
            },
        )
