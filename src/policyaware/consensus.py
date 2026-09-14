from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Protocol

from pydantic import BaseModel, Field

from policyaware.models import DataFindings, Decision, GatewayRequest, RiskTier


class ConsensusVote(BaseModel):
    voter: str
    decision: Decision
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reason: str
    reason_codes: list[str] = Field(default_factory=list)


class ConsensusResult(BaseModel):
    decision: Decision
    quorum_met: bool
    required_votes: int
    total_votes: int
    allow_votes: int
    deny_votes: int
    approval_votes: int
    votes: list[ConsensusVote] = Field(default_factory=list)
    reason: str
    reason_codes: list[str] = Field(default_factory=list)


class ConsensusJuror(Protocol):
    name: str

    def vote(
        self,
        request: GatewayRequest,
        findings: DataFindings | None = None,
        risk_tier: RiskTier = RiskTier.LOW,
    ) -> ConsensusVote:
        ...


@dataclass
class RuleBasedConsensusJuror:
    """Small deterministic juror for high-risk policy review.

    This is intentionally lightweight. Production teams can replace it with a
    model-backed, service-backed, or domain-specific juror that implements the
    same vote method.
    """

    name: str
    deny_on_sensitive_data: bool = False
    approval_on_high_risk: bool = True
    deny_on_critical_risk: bool = True
    blocked_terms: list[str] = field(default_factory=list)

    def vote(
        self,
        request: GatewayRequest,
        findings: DataFindings | None = None,
        risk_tier: RiskTier = RiskTier.LOW,
    ) -> ConsensusVote:
        prompt = request.prompt_text.lower()
        findings = findings or DataFindings()

        if self.deny_on_sensitive_data and findings.contains_sensitive:
            return ConsensusVote(
                voter=self.name,
                decision=Decision.DENY,
                confidence=0.95,
                reason="Sensitive data was present for a juror that denies sensitive payloads.",
                reason_codes=["CONSENSUS.SENSITIVE_DATA_DENY"],
            )

        if any(term.lower() in prompt for term in self.blocked_terms):
            return ConsensusVote(
                voter=self.name,
                decision=Decision.DENY,
                confidence=0.9,
                reason="The request matched a blocked term for this juror.",
                reason_codes=["CONSENSUS.BLOCKED_TERM"],
            )

        if self.deny_on_critical_risk and risk_tier == RiskTier.CRITICAL:
            return ConsensusVote(
                voter=self.name,
                decision=Decision.DENY,
                confidence=0.92,
                reason="Critical-risk requests are denied by this juror.",
                reason_codes=["CONSENSUS.CRITICAL_RISK_DENY"],
            )

        if self.approval_on_high_risk and risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}:
            return ConsensusVote(
                voter=self.name,
                decision=Decision.REQUIRE_APPROVAL,
                confidence=0.85,
                reason="High-risk requests require human approval.",
                reason_codes=["CONSENSUS.HIGH_RISK_APPROVAL"],
            )

        return ConsensusVote(
            voter=self.name,
            decision=Decision.ALLOW,
            confidence=0.8,
            reason="No juror-specific risk condition matched.",
            reason_codes=[],
        )


class JuryConsensusEngine:
    """Quorum-based safety decision across independent jurors."""

    def __init__(
        self,
        jurors: list[ConsensusJuror] | None = None,
        *,
        quorum: int | None = None,
        deny_veto: bool = True,
    ):
        self.jurors = jurors or default_jurors()
        self.quorum = quorum or max(1, (len(self.jurors) // 2) + 1)
        self.deny_veto = deny_veto

    def decide(
        self,
        request: GatewayRequest,
        findings: DataFindings | None = None,
        risk_tier: RiskTier = RiskTier.LOW,
    ) -> ConsensusResult:
        votes = [juror.vote(request, findings, risk_tier) for juror in self.jurors]
        return self._summarize(votes)

    async def adecide(
        self,
        request: GatewayRequest,
        findings: DataFindings | None = None,
        risk_tier: RiskTier = RiskTier.LOW,
    ) -> ConsensusResult:
        async def vote(juror: ConsensusJuror) -> ConsensusVote:
            return await asyncio.to_thread(juror.vote, request, findings, risk_tier)

        votes = await asyncio.gather(*(vote(juror) for juror in self.jurors))
        return self._summarize(list(votes))

    def _summarize(self, votes: list[ConsensusVote]) -> ConsensusResult:
        allow_votes = sum(1 for vote in votes if vote.decision in {Decision.ALLOW, Decision.CONDITIONAL_ALLOW})
        deny_votes = sum(1 for vote in votes if vote.decision == Decision.DENY)
        approval_votes = sum(1 for vote in votes if vote.decision == Decision.REQUIRE_APPROVAL)
        reason_codes = sorted({code for vote in votes for code in vote.reason_codes})

        if self.deny_veto and deny_votes:
            return ConsensusResult(
                decision=Decision.DENY,
                quorum_met=True,
                required_votes=self.quorum,
                total_votes=len(votes),
                allow_votes=allow_votes,
                deny_votes=deny_votes,
                approval_votes=approval_votes,
                votes=votes,
                reason="At least one consensus juror issued a deny veto.",
                reason_codes=reason_codes or ["CONSENSUS.DENY_VETO"],
            )

        if approval_votes >= self.quorum:
            return ConsensusResult(
                decision=Decision.REQUIRE_APPROVAL,
                quorum_met=True,
                required_votes=self.quorum,
                total_votes=len(votes),
                allow_votes=allow_votes,
                deny_votes=deny_votes,
                approval_votes=approval_votes,
                votes=votes,
                reason="Consensus quorum requires human approval.",
                reason_codes=reason_codes or ["CONSENSUS.APPROVAL_QUORUM"],
            )

        if allow_votes >= self.quorum:
            return ConsensusResult(
                decision=Decision.ALLOW,
                quorum_met=True,
                required_votes=self.quorum,
                total_votes=len(votes),
                allow_votes=allow_votes,
                deny_votes=deny_votes,
                approval_votes=approval_votes,
                votes=votes,
                reason="Consensus quorum allowed the request.",
                reason_codes=reason_codes,
            )

        return ConsensusResult(
            decision=Decision.REQUIRE_APPROVAL,
            quorum_met=False,
            required_votes=self.quorum,
            total_votes=len(votes),
            allow_votes=allow_votes,
            deny_votes=deny_votes,
            approval_votes=approval_votes,
            votes=votes,
            reason="Consensus quorum was not reached.",
            reason_codes=reason_codes or ["CONSENSUS.QUORUM_NOT_MET"],
        )


def default_jurors() -> list[RuleBasedConsensusJuror]:
    return [
        RuleBasedConsensusJuror(
            name="data_safety",
            deny_on_sensitive_data=True,
            approval_on_high_risk=True,
        ),
        RuleBasedConsensusJuror(
            name="tool_safety",
            blocked_terms=["delete database", "drop table", "transfer funds"],
            approval_on_high_risk=True,
        ),
        RuleBasedConsensusJuror(
            name="risk_owner",
            approval_on_high_risk=True,
            deny_on_critical_risk=True,
        ),
    ]
