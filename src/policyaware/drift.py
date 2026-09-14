from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from pydantic import BaseModel, Field


class DriftCanaryCase(BaseModel):
    case_id: str
    prompt: str
    expected_contains: list[str] = Field(default_factory=list)
    forbidden_contains: list[str] = Field(default_factory=list)


class DriftCanaryFinding(BaseModel):
    case_id: str
    passed: bool
    score: float
    reason: str


class DriftCanaryReport(BaseModel):
    passed: bool
    drift_score: float
    threshold: float
    findings: list[DriftCanaryFinding] = Field(default_factory=list)


@dataclass
class DriftCanaryEngine:
    """Run deterministic baseline canaries against active model callables."""

    threshold: float = 0.2

    def run(
        self,
        cases: list[DriftCanaryCase],
        model_call: Callable[[str], str],
    ) -> DriftCanaryReport:
        findings = [self._run_case(case, model_call(case.prompt)) for case in cases]
        failures = [finding for finding in findings if not finding.passed]
        drift_score = len(failures) / len(findings) if findings else 0.0
        return DriftCanaryReport(
            passed=drift_score <= self.threshold,
            drift_score=drift_score,
            threshold=self.threshold,
            findings=findings,
        )

    def _run_case(self, case: DriftCanaryCase, output: str) -> DriftCanaryFinding:
        normalized = output.lower()
        missing = [item for item in case.expected_contains if item.lower() not in normalized]
        forbidden = [item for item in case.forbidden_contains if item.lower() in normalized]
        passed = not missing and not forbidden
        score = 1.0 if passed else 0.0
        reason_parts = []
        if missing:
            reason_parts.append(f"Missing expected content: {', '.join(missing)}.")
        if forbidden:
            reason_parts.append(f"Forbidden content appeared: {', '.join(forbidden)}.")
        return DriftCanaryFinding(
            case_id=case.case_id,
            passed=passed,
            score=score,
            reason=" ".join(reason_parts) if reason_parts else "Model behavior matched the canary.",
        )
