from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Deque, Literal

from pydantic import BaseModel, Field


CircuitAction = Literal["allow", "pause", "require_approval", "deny"]


class CircuitBreakerDecision(BaseModel):
    allowed: bool
    action: CircuitAction
    reason: str
    reason_codes: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    snapshot: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class BudgetEvent:
    timestamp: float
    session_id: str
    agent_id: str
    tool: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


class BudgetCircuitBreaker:
    """In-memory token, cost, and tool-rate circuit breaker."""

    def __init__(
        self,
        *,
        max_cost_usd_per_session: float = 5.0,
        max_tokens_per_session: int = 50_000,
        max_tool_calls_per_window: int = 10,
        window_seconds: int = 60,
        escalation_action: CircuitAction = "require_approval",
    ):
        self.max_cost_usd_per_session = max_cost_usd_per_session
        self.max_tokens_per_session = max_tokens_per_session
        self.max_tool_calls_per_window = max_tool_calls_per_window
        self.window_seconds = window_seconds
        self.escalation_action = escalation_action
        self._events: dict[str, Deque[BudgetEvent]] = defaultdict(deque)

    def record(
        self,
        *,
        session_id: str,
        agent_id: str,
        tool: str | None = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> CircuitBreakerDecision:
        now = time.time()
        event = BudgetEvent(
            timestamp=now,
            session_id=session_id,
            agent_id=agent_id,
            tool=tool,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
        )
        events = self._events[session_id]
        events.append(event)
        self._compact(events, now)
        metrics = self._metrics(session_id, now)

        if metrics["session_cost_usd"] > self.max_cost_usd_per_session:
            return self._blocked(
                action=self.escalation_action,
                reason="Session exceeded the configured cost circuit breaker.",
                code="CIRCUIT.COST_LIMIT_EXCEEDED",
                metrics=metrics,
            )

        if metrics["session_tokens"] > self.max_tokens_per_session:
            return self._blocked(
                action=self.escalation_action,
                reason="Session exceeded the configured token circuit breaker.",
                code="CIRCUIT.TOKEN_LIMIT_EXCEEDED",
                metrics=metrics,
            )

        if tool and metrics["tool_calls_in_window"].get(tool, 0) > self.max_tool_calls_per_window:
            return self._blocked(
                action=self.escalation_action,
                reason="Tool call rate exceeded the configured window circuit breaker.",
                code="CIRCUIT.TOOL_RATE_LIMIT_EXCEEDED",
                metrics=metrics,
            )

        return CircuitBreakerDecision(
            allowed=True,
            action="allow",
            reason="Budget and rate usage remain within configured circuit breakers.",
            metrics=metrics,
            snapshot=self.snapshot(session_id),
        )

    def snapshot(self, session_id: str) -> dict[str, Any]:
        now = time.time()
        return {
            "session_id": session_id,
            "window_seconds": self.window_seconds,
            "limits": {
                "max_cost_usd_per_session": self.max_cost_usd_per_session,
                "max_tokens_per_session": self.max_tokens_per_session,
                "max_tool_calls_per_window": self.max_tool_calls_per_window,
            },
            "metrics": self._metrics(session_id, now),
        }

    def _compact(self, events: Deque[BudgetEvent], now: float) -> None:
        max_age = max(self.window_seconds * 4, self.window_seconds)
        while events and now - events[0].timestamp > max_age:
            events.popleft()

    def _metrics(self, session_id: str, now: float) -> dict[str, Any]:
        events = list(self._events.get(session_id, []))
        window_start = now - self.window_seconds
        tool_calls_in_window: dict[str, int] = {}
        for event in events:
            if event.tool and event.timestamp >= window_start:
                tool_calls_in_window[event.tool] = tool_calls_in_window.get(event.tool, 0) + 1
        return {
            "session_cost_usd": round(sum(event.cost_usd for event in events), 6),
            "session_tokens": sum(event.input_tokens + event.output_tokens for event in events),
            "events": len(events),
            "tool_calls_in_window": tool_calls_in_window,
        }

    def _blocked(
        self,
        *,
        action: CircuitAction,
        reason: str,
        code: str,
        metrics: dict[str, Any],
    ) -> CircuitBreakerDecision:
        return CircuitBreakerDecision(
            allowed=False,
            action=action,
            reason=reason,
            reason_codes=[code],
            metrics=metrics,
            snapshot={"paused_at": time.time(), "metrics": metrics},
        )
