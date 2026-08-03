from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from typing import Any

from policyaware.data_protection import DataProtectionEngine
from policyaware.models import (
    DataFindings,
    Decision,
    GatewayRequest,
    PolicyDecision,
    RiskTier,
    ToolCallRequest,
    ToolDecision,
)


@dataclass
class SessionState:
    session_id: str
    requests: int = 0
    tool_calls: int = 0
    sensitive_findings: int = 0
    output_sensitive_findings: int = 0
    categories: dict[str, int] = field(default_factory=dict)
    tool_actions: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "requests": self.requests,
            "tool_calls": self.tool_calls,
            "sensitive_findings": self.sensitive_findings,
            "output_sensitive_findings": self.output_sensitive_findings,
            "categories": dict(self.categories),
            "tool_actions": dict(self.tool_actions),
        }


@dataclass(frozen=True)
class SessionSignal:
    allowed: bool
    reason: str
    reason_codes: list[str] = field(default_factory=list)
    state: dict[str, Any] = field(default_factory=dict)


class SessionStateStore(Protocol):
    def get(self, session_id: str) -> SessionState | None:
        ...

    def put(self, state: SessionState) -> None:
        ...


class InMemorySessionStateStore:
    def __init__(self) -> None:
        self._states: dict[str, SessionState] = {}

    def get(self, session_id: str) -> SessionState | None:
        return self._states.get(session_id)

    def put(self, state: SessionState) -> None:
        self._states[state.session_id] = state


class SQLiteSessionStateStore:
    def __init__(self, path: str | Path = ".policyaware/session-state.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_state (
                    session_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL
                )
                """
            )

    def get(self, session_id: str) -> SessionState | None:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "SELECT state_json FROM session_state WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if not row:
            return None
        data = json.loads(row[0])
        return SessionState(
            session_id=data["session_id"],
            requests=int(data.get("requests", 0)),
            tool_calls=int(data.get("tool_calls", 0)),
            sensitive_findings=int(data.get("sensitive_findings", 0)),
            output_sensitive_findings=int(data.get("output_sensitive_findings", 0)),
            categories=dict(data.get("categories", {})),
            tool_actions=dict(data.get("tool_actions", {})),
        )

    def put(self, state: SessionState) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO session_state (session_id, state_json)
                VALUES (?, ?)
                """,
                (state.session_id, json.dumps(state.to_dict())),
            )


class SessionStateMonitor:
    """Stateful inspection for multi-turn leakage and repeated tool activity."""

    def __init__(
        self,
        *,
        max_sensitive_findings_per_session: int = 10,
        max_output_sensitive_findings_per_session: int = 3,
        max_tool_calls_per_session: int = 25,
        max_same_tool_action_per_session: int = 10,
        data_protection: DataProtectionEngine | None = None,
        store: SessionStateStore | None = None,
    ):
        self.max_sensitive_findings_per_session = max_sensitive_findings_per_session
        self.max_output_sensitive_findings_per_session = max_output_sensitive_findings_per_session
        self.max_tool_calls_per_session = max_tool_calls_per_session
        self.max_same_tool_action_per_session = max_same_tool_action_per_session
        self.data_protection = data_protection or DataProtectionEngine()
        self.store = store or InMemorySessionStateStore()

    def session_id_for_request(self, request: GatewayRequest) -> str:
        return str(
            request.metadata.get("session_id")
            or request.context.get("session_id")
            or request.context.get("conversation_id")
            or request.user.get("id")
            or f"{request.tenant}:{request.app}:anonymous"
        )

    def session_id_for_tool_call(self, request: ToolCallRequest) -> str:
        return str(
            request.context.get("session_id")
            or request.context.get("conversation_id")
            or request.user.get("id")
            or f"{request.tenant}:{request.agent_id}"
        )

    def state(self, session_id: str) -> SessionState:
        state = self.store.get(session_id)
        if state is None:
            state = SessionState(session_id=session_id)
            self.store.put(state)
        return state

    def observe_request(self, request: GatewayRequest, findings: DataFindings) -> SessionSignal:
        session_id = self.session_id_for_request(request)
        state = self.state(session_id)
        state.requests += 1
        self._add_findings(state, findings, output=False)
        self.store.put(state)
        return self._request_signal(state)

    def observe_output(self, request: GatewayRequest, output: str) -> SessionSignal:
        session_id = self.session_id_for_request(request)
        state = self.state(session_id)
        findings = self.data_protection.inspect(output)
        self._add_findings(state, findings, output=True)
        self.store.put(state)
        return self._output_signal(state)

    def observe_tool_call(self, request: ToolCallRequest) -> SessionSignal:
        session_id = self.session_id_for_tool_call(request)
        state = self.state(session_id)
        state.tool_calls += 1
        action_key = f"{request.connector_id}.{request.action}"
        state.tool_actions[action_key] = state.tool_actions.get(action_key, 0) + 1
        self.store.put(state)
        if state.tool_calls > self.max_tool_calls_per_session:
            return SessionSignal(
                allowed=False,
                reason="Session exceeded the allowed number of tool calls.",
                reason_codes=["SESSION.TOOL_CALL_LIMIT_EXCEEDED"],
                state=state.to_dict(),
            )
        if state.tool_actions[action_key] > self.max_same_tool_action_per_session:
            return SessionSignal(
                allowed=False,
                reason="Session repeatedly called the same tool action above the configured threshold.",
                reason_codes=["SESSION.REPEATED_TOOL_ACTION"],
                state=state.to_dict(),
            )
        return SessionSignal(
            allowed=True,
            reason="Session tool activity is within configured thresholds.",
            reason_codes=[],
            state=state.to_dict(),
        )

    def deny_decision(self, signal: SessionSignal) -> PolicyDecision:
        return PolicyDecision(
            decision=Decision.DENY,
            reason=signal.reason,
            risk_tier=RiskTier.HIGH,
            risk_score=0.85,
            reason_codes=signal.reason_codes,
            violated_rules=["session_state_monitor"],
            remediation=[
                "Review cumulative session behavior, reduce sensitive-data exposure, or route to approval."
            ],
        )

    def deny_tool_decision(self, request: ToolCallRequest, signal: SessionSignal) -> ToolDecision:
        return ToolDecision(
            decision=Decision.DENY,
            connector_id=request.connector_id,
            action=request.action,
            reason=signal.reason,
            reason_codes=signal.reason_codes,
            matched_rules=["session_state_monitor"],
            limits=signal.state,
        )

    def _add_findings(self, state: SessionState, findings: DataFindings, *, output: bool) -> None:
        count = findings.redactions or len(findings.categories)
        if findings.contains_sensitive:
            if output:
                state.output_sensitive_findings += count
            else:
                state.sensitive_findings += count
        for category in findings.categories:
            state.categories[category] = state.categories.get(category, 0) + 1

    def _request_signal(self, state: SessionState) -> SessionSignal:
        if state.sensitive_findings > self.max_sensitive_findings_per_session:
            return SessionSignal(
                allowed=False,
                reason="Session exceeded cumulative sensitive-data threshold.",
                reason_codes=["SESSION.CUMULATIVE_SENSITIVE_DATA"],
                state=state.to_dict(),
            )
        return SessionSignal(
            allowed=True,
            reason="Session request activity is within configured thresholds.",
            reason_codes=[],
            state=state.to_dict(),
        )

    def _output_signal(self, state: SessionState) -> SessionSignal:
        if state.output_sensitive_findings > self.max_output_sensitive_findings_per_session:
            return SessionSignal(
                allowed=False,
                reason="Session exceeded cumulative output sensitive-data threshold.",
                reason_codes=["SESSION.CUMULATIVE_OUTPUT_LEAKAGE"],
                state=state.to_dict(),
            )
        return SessionSignal(
            allowed=True,
            reason="Session output activity is within configured thresholds.",
            reason_codes=[],
            state=state.to_dict(),
        )
