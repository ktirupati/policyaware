from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    CONDITIONAL_ALLOW = "conditional_allow"
    REQUIRE_APPROVAL = "require_approval"


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GatewayRequest(BaseModel):
    tenant: str
    app: str
    user: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    messages: list[dict[str, str]] = Field(default_factory=list)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    request_id: str = Field(default_factory=lambda: f"req_{uuid4().hex}")

    @property
    def prompt_text(self) -> str:
        return "\n".join(message.get("content", "") for message in self.messages)


class DataFindings(BaseModel):
    contains_pii: bool = False
    contains_phi: bool = False
    contains_secrets: bool = False
    categories: list[str] = Field(default_factory=list)
    redactions: int = 0
    redacted_text: str | None = None

    @property
    def contains_sensitive(self) -> bool:
        return self.contains_pii or self.contains_phi or self.contains_secrets


class MLSignal(BaseModel):
    name: str
    label: str | None = None
    score: float = 0.0
    detected: bool = False
    provider: str | None = None
    model: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class MLAssessment(BaseModel):
    signals: dict[str, MLSignal] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def as_policy_context(self) -> dict[str, Any]:
        return {
            name: signal.model_dump(mode="json")
            for name, signal in self.signals.items()
        }


class RiskAssessment(BaseModel):
    tier: RiskTier
    score: float
    factors: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    fail_safe: str = "deny"


class DecisionExplanation(BaseModel):
    decision: Decision
    summary: str
    reason_codes: list[str] = Field(default_factory=list)
    matched_policy_ids: list[str] = Field(default_factory=list)
    violated_policy_ids: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    decision: Decision
    actions: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    reason: str
    risk_score: float = 0.0
    risk_tier: RiskTier = RiskTier.LOW
    reason_codes: list[str] = Field(default_factory=list)
    violated_rules: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    explanation: DecisionExplanation | None = None


class ModelCandidate(BaseModel):
    name: str
    provider: str = "local"
    capabilities: list[Literal["text", "embeddings", "rerank", "tools"]] = Field(
        default_factory=lambda: ["text"]
    )
    region: str = "us"
    max_tokens: int = 8192
    cost_per_1k_tokens: float = 0.0
    quality_score: float = 0.8
    available: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class RouteDecision(BaseModel):
    model: ModelCandidate
    fallback_used: bool = False
    reason: str


class EvalResult(BaseModel):
    name: str
    passed: bool
    score: float
    reason: str
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"


class ToolCallRequest(BaseModel):
    agent_id: str
    connector_id: str
    action: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    tenant: str = "default"
    user: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    call_id: str = Field(default_factory=lambda: f"tool_{uuid4().hex}")


class ToolDecision(BaseModel):
    decision: Decision
    connector_id: str
    action: str
    reason: str
    reason_codes: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    limits: dict[str, Any] = Field(default_factory=dict)
    approval_required: bool = False


class GatewayResponse(BaseModel):
    content: str
    policy: PolicyDecision
    route: RouteDecision | None = None
    evals: list[EvalResult] = Field(default_factory=list)
    trace_id: str = Field(default_factory=lambda: f"trc_{uuid4().hex}")
    metadata: dict[str, Any] = Field(default_factory=dict)
    risk: RiskAssessment | None = None


class AuditTrace(BaseModel):
    schema_version: str = "0.2"
    trace_id: str
    request_id: str
    tenant: str
    app: str
    user_id: str | None = None
    task_type: str | None = None
    policy_decision: str
    matched_rules: list[str]
    reason_codes: list[str] = Field(default_factory=list)
    actions: list[str]
    risk_tier: str = "low"
    model: str | None = None
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float
    latency_ms: int
    risk_score: float
    eval_scores: dict[str, float] = Field(default_factory=dict)
    request_snapshot: dict[str, Any] = Field(default_factory=dict)
    response_snapshot: dict[str, Any] = Field(default_factory=dict)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ApprovalRequest(BaseModel):
    approval_id: str = Field(default_factory=lambda: f"apr_{uuid4().hex}")
    tenant: str
    app: str
    user: dict[str, Any] = Field(default_factory=dict)
    decision: PolicyDecision
    request_snapshot: dict[str, Any] = Field(default_factory=dict)
    status: Literal["pending", "approved", "denied"] = "pending"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvalCaseResult(BaseModel):
    case_id: str
    passed: bool
    results: list[EvalResult] = Field(default_factory=list)
    decision: str | None = None
    reason_codes: list[str] = Field(default_factory=list)


class EvalReport(BaseModel):
    suite: str
    run_id: str = Field(default_factory=lambda: f"eval_{uuid4().hex}")
    cases: int = 0
    passed: int = 0
    failed: int = 0
    policy_compliance_score: float = 0.0
    safety_score: float = 0.0
    results: list[EvalCaseResult] = Field(default_factory=list)
