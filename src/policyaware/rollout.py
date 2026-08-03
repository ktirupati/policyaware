from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from policyaware.models import DataFindings, GatewayRequest, PolicyDecision, RiskAssessment
from policyaware.policy import PolicyEngine


@dataclass
class PolicyRollout:
    """Evaluate or enforce a candidate policy for a percentage of traffic."""

    candidate_engine: PolicyEngine
    name: str = "candidate"
    mode: Literal["shadow", "enforce"] = "shadow"
    percentage: int = 100

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        name: str = "candidate",
        mode: Literal["shadow", "enforce"] = "shadow",
        percentage: int = 100,
    ) -> "PolicyRollout":
        if percentage < 0 or percentage > 100:
            raise ValueError("Rollout percentage must be between 0 and 100.")
        return cls(
            candidate_engine=PolicyEngine.from_file(path),
            name=name,
            mode=mode,
            percentage=percentage,
        )

    def selected(self, request: GatewayRequest) -> bool:
        if self.percentage >= 100:
            return True
        if self.percentage <= 0:
            return False
        key = f"{request.tenant}:{request.app}:{request.user.get('id')}:{request.request_id}"
        bucket = int(hashlib.sha256(key.encode("utf-8")).hexdigest()[:8], 16) % 100
        return bucket < self.percentage

    def decide(
        self,
        request: GatewayRequest,
        findings: DataFindings,
        risk: RiskAssessment,
    ) -> PolicyDecision | None:
        if not self.selected(request):
            return None
        return self.candidate_engine.decide(request, findings, risk)

