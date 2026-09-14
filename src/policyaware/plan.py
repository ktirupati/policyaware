from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class PlanStep(BaseModel):
    id: str | None = None
    tool: str | None = None
    connector: str | None = None
    action: str | None = None
    prompt: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)


class PlanFinding(BaseModel):
    severity: str
    step: int
    title: str
    reason: str
    recommendation: str


class PlanCheckReport(BaseModel):
    steps_checked: int
    allowed: bool
    highest_severity: str = "none"
    findings: list[PlanFinding] = Field(default_factory=list)


class PlanPreflightChecker:
    """Fast deterministic preflight for proposed multi-step agent plans."""

    RISKY_ACTION_RE = re.compile(
        r"\b(delete|drop|destroy|refund|payment|transfer|deploy|merge|permission|exec|shell)\b",
        re.I,
    )
    EXFIL_RE = re.compile(
        r"\b(email|upload|post|send|webhook|external|http|s3://|gs://|abfss?://)\b",
        re.I,
    )
    LOOP_RE = re.compile(r"\b(loop|repeat|retry_forever|while true|run_forever)\b", re.I)

    def check(self, plan: dict[str, Any] | list[Any]) -> PlanCheckReport:
        steps = _normalize_steps(plan)
        findings: list[PlanFinding] = []
        side_effects = 0
        external_sends = 0

        for index, step in enumerate(steps, start=1):
            text = _step_text(step)
            if self.RISKY_ACTION_RE.search(text):
                side_effects += 1
                findings.append(
                    PlanFinding(
                        severity="high",
                        step=index,
                        title="Risky side-effecting action in proposed plan",
                        reason="Plan step appears to modify, deploy, delete, transfer, or execute.",
                        recommendation="Require approval or rewrite the plan to read-only actions first.",
                    )
                )
            if self.EXFIL_RE.search(text):
                external_sends += 1
                findings.append(
                    PlanFinding(
                        severity="medium",
                        step=index,
                        title="External transfer or data movement signal in proposed plan",
                        reason="Plan step mentions sending, posting, uploading, or external storage.",
                        recommendation="Apply data-protection checks and approval before external transfer.",
                    )
                )
            if self.LOOP_RE.search(text):
                findings.append(
                    PlanFinding(
                        severity="medium",
                        step=index,
                        title="Looping or repeated execution signal in proposed plan",
                        reason="Plan step may repeat actions and compound cost or side effects.",
                        recommendation="Add max-iteration, budget, and timeout limits before execution.",
                    )
                )

        if side_effects >= 2:
            findings.append(
                PlanFinding(
                    severity="critical",
                    step=0,
                    title="Cascading high-impact plan trajectory",
                    reason="Multiple side-effecting steps can compound risk before runtime checks react.",
                    recommendation="Run human review or split the workflow into approved subplans.",
                )
            )
        if side_effects and external_sends:
            findings.append(
                PlanFinding(
                    severity="high",
                    step=0,
                    title="Side effect followed by possible external data movement",
                    reason="The plan combines action execution with external transfer signals.",
                    recommendation="Require approval and audit before the first real tool call.",
                )
            )

        highest = _highest_severity(findings)
        return PlanCheckReport(
            steps_checked=len(steps),
            allowed=highest not in {"critical", "high"},
            highest_severity=highest,
            findings=findings,
        )

    def check_file(self, path: Path) -> PlanCheckReport:
        raw = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            return self.check(json.loads(raw))
        return self.check(yaml.safe_load(raw) or {})


def _normalize_steps(plan: dict[str, Any] | list[Any]) -> list[PlanStep]:
    raw_steps = plan
    if isinstance(plan, dict):
        raw_steps = plan.get("steps") or plan.get("plan") or []
    if not isinstance(raw_steps, list):
        raw_steps = [raw_steps]
    steps: list[PlanStep] = []
    for index, item in enumerate(raw_steps, start=1):
        if isinstance(item, dict):
            steps.append(PlanStep(id=str(item.get("id", index)), **{k: v for k, v in item.items() if k != "id"}))
        else:
            steps.append(PlanStep(id=str(index), prompt=str(item)))
    return steps


def _step_text(step: PlanStep) -> str:
    return " ".join(
        [
            step.tool or "",
            step.connector or "",
            step.action or "",
            step.prompt or "",
            json.dumps(step.arguments, sort_keys=True),
        ]
    )


def _highest_severity(findings: list[PlanFinding]) -> str:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    if not findings:
        return "none"
    return min((finding.severity for finding in findings), key=lambda value: order.get(value, 9))
