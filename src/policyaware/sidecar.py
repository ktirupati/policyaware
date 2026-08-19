from __future__ import annotations

import json
from hmac import compare_digest
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from policyaware.audit import AuditLogger
from policyaware.evals import RuntimeEvaluator
from policyaware.emergency import EmergencyRevokeList
from policyaware.gateway import Gateway
from policyaware.integrity import IntegritySigner
from policyaware.models import GatewayRequest, ToolCallRequest
from policyaware.rejections import policy_rejection, tool_rejection
from policyaware.rollout import PolicyRollout
from policyaware.session_state import SessionStateMonitor
from policyaware.tools import ToolPolicyEngine


class PolicyAwareSidecar:
    """Small dependency-free HTTP sidecar for non-Python services."""

    def __init__(
        self,
        gateway: Gateway,
        tool_engine: ToolPolicyEngine | None = None,
        *,
        auth_token: str | None = None,
        session_monitor: SessionStateMonitor | None = None,
        emergency_revoke: EmergencyRevokeList | None = None,
        policy_rollout: PolicyRollout | None = None,
    ):
        self.gateway = gateway
        self.tool_engine = tool_engine
        self.evaluator = RuntimeEvaluator(gateway.data_protection)
        self.auth_token = auth_token
        self.session_monitor = session_monitor
        self.emergency_revoke = emergency_revoke
        self.policy_rollout = policy_rollout

    @classmethod
    def from_files(
        cls,
        policy_file: str | Path,
        tool_policy_file: str | Path | None = None,
        *,
        auth_token: str | None = None,
        policy_auth_token: str | None = None,
        policy_cache_file: str | Path | None = None,
        policy_refresh_seconds: float = 60.0,
        policy_timeout_seconds: float = 5.0,
        policy_retry_base_seconds: float = 1.0,
        policy_retry_max_seconds: float = 60.0,
        policy_retry_jitter_seconds: float = 0.25,
        fail_closed: bool = True,
        session_monitor: SessionStateMonitor | None = None,
        emergency_revoke_file: str | Path | None = None,
        policy_sha256: str | None = None,
        fallback_policy_file: str | Path | None = None,
        audit_signing_secret: str | None = None,
        policy_rollout: PolicyRollout | None = None,
    ) -> "PolicyAwareSidecar":
        gateway = Gateway.from_policy_source(
            policy_file,
            refresh_seconds=policy_refresh_seconds,
            fail_closed=fail_closed,
            auth_token=policy_auth_token,
            cache_file=policy_cache_file,
            timeout_seconds=policy_timeout_seconds,
            expected_sha256=policy_sha256,
            fallback_policy_file=fallback_policy_file,
            retry_base_seconds=policy_retry_base_seconds,
            retry_max_seconds=policy_retry_max_seconds,
            retry_jitter_seconds=policy_retry_jitter_seconds,
        )
        tool_engine = ToolPolicyEngine.from_file(tool_policy_file) if tool_policy_file else None
        gateway.session_monitor = session_monitor or gateway.session_monitor
        gateway.emergency_revoke = (
            EmergencyRevokeList.from_file(emergency_revoke_file)
            if emergency_revoke_file
            else gateway.emergency_revoke
        )
        if audit_signing_secret:
            gateway.audit_logger = AuditLogger(
                Path(".policyaware/traces.jsonl"),
                signer=IntegritySigner(audit_signing_secret),
            )
        gateway.policy_rollout = policy_rollout or gateway.policy_rollout
        return cls(
            gateway=gateway,
            tool_engine=tool_engine,
            auth_token=auth_token,
            session_monitor=gateway.session_monitor,
            emergency_revoke=gateway.emergency_revoke,
            policy_rollout=gateway.policy_rollout,
        )

    def handle(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any] | str]:
        if method == "GET" and path == "/health":
            return 200, {"status": "ok", "service": "policyaware-sidecar"}
        if method == "GET" and path == "/metrics":
            if not self._authorized(headers or {}):
                return 401, {"error": "unauthorized", "detail": "valid bearer token required"}
            return 200, self.gateway.telemetry.prometheus_text()
        if method != "POST":
            return 405, {"error": "method_not_allowed"}
        if not self._authorized(headers or {}):
            return 401, {"error": "unauthorized", "detail": "valid bearer token required"}
        body = body or {}
        try:
            if path == "/v1/check":
                return 200, self._check(body)
            if path == "/v1/tool/check":
                return 200, self._tool_check(body)
            if path == "/v1/route":
                return 200, self._route(body)
            if path == "/v1/evaluate":
                return 200, self._evaluate(body)
        except (ValidationError, ValueError, KeyError) as exc:
            return 400, {"error": "bad_request", "detail": str(exc)}
        return 404, {"error": "not_found"}

    def _authorized(self, headers: dict[str, str]) -> bool:
        if not self.auth_token:
            return True
        authorization = headers.get("authorization") or headers.get("Authorization") or ""
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            return False
        supplied = authorization[len(prefix) :].strip()
        return compare_digest(supplied, self.auth_token)

    def _check(self, body: dict[str, Any]) -> dict[str, Any]:
        request = _gateway_request_from_body(body)
        response = self.gateway.chat(request)
        payload = {
            "allowed": response.policy.decision.value in {"allow", "conditional_allow"},
            "decision": response.policy.decision.value,
            "reason": response.policy.reason,
            "reason_codes": response.policy.reason_codes,
            "matched_rules": response.policy.matched_rules,
            "risk_tier": response.policy.risk_tier.value,
            "trace_id": response.trace_id,
            "content": response.content,
        }
        rejection = policy_rejection(response)
        if rejection:
            payload["rejection"] = rejection.model_dump(mode="json")
        return payload

    def _tool_check(self, body: dict[str, Any]) -> dict[str, Any]:
        if self.tool_engine is None:
            raise ValueError("tool_policy_file is required for /v1/tool/check")
        request = ToolCallRequest(**body)
        if self.emergency_revoke:
            revoke_match = self.emergency_revoke.check_tool_call(request)
            if revoke_match.matched:
                decision = self.emergency_revoke.deny_tool_decision(request, revoke_match)
                self._record_tool_telemetry(
                    request,
                    decision.decision.value,
                    decision.approval_required,
                    decision.reason_codes,
                    decision.matched_rules,
                )
                payload = {
                    "allowed": False,
                    "decision": decision.decision.value,
                    "approval_required": decision.approval_required,
                    "connector_id": decision.connector_id,
                    "action": decision.action,
                    "reason": decision.reason,
                    "reason_codes": decision.reason_codes,
                    "matched_rules": decision.matched_rules,
                    "limits": decision.limits,
                    "session": None,
                }
                rejection = tool_rejection(decision)
                if rejection:
                    payload["rejection"] = rejection.model_dump(mode="json")
                return payload
        session_signal = self.session_monitor.observe_tool_call(request) if self.session_monitor else None
        decision = (
            self.session_monitor.deny_tool_decision(request, session_signal)
            if session_signal and not session_signal.allowed
            else self.tool_engine.decide(request)
        )
        self._record_tool_telemetry(
            request,
            decision.decision.value,
            decision.approval_required,
            decision.reason_codes,
            decision.matched_rules,
        )
        payload = {
            "allowed": decision.decision.value == "allow",
            "decision": decision.decision.value,
            "approval_required": decision.approval_required,
            "connector_id": decision.connector_id,
            "action": decision.action,
            "reason": decision.reason,
            "reason_codes": decision.reason_codes,
            "matched_rules": decision.matched_rules,
            "limits": decision.limits,
            "session": session_signal.state if session_signal else None,
        }
        rejection = tool_rejection(
            decision,
            metadata={"session": session_signal.state} if session_signal else None,
        )
        if rejection:
            payload["rejection"] = rejection.model_dump(mode="json")
        return payload

    def _route(self, body: dict[str, Any]) -> dict[str, Any]:
        request = _gateway_request_from_body(body)
        findings = self.gateway.data_protection.redact(request.prompt_text)
        risk = self.gateway.risk_classifier.classify(request, findings)
        decision = self.gateway.policy_engine.decide(request, findings, risk)
        route = self.gateway.router.route(request, decision)
        return {
            "decision": decision.decision.value,
            "risk_tier": risk.tier.value,
            "model": route.model.model_dump(mode="json"),
            "fallback_used": route.fallback_used,
            "reason": route.reason,
        }

    def _evaluate(self, body: dict[str, Any]) -> dict[str, Any]:
        request = _gateway_request_from_body(body)
        output = str(body.get("output", body.get("response", "")))
        results = self.evaluator.evaluate(request, output)
        return {"results": [result.model_dump(mode="json") for result in results]}

    def _record_tool_telemetry(
        self,
        request: ToolCallRequest,
        decision: str,
        approval_required: bool,
        reason_codes: list[str],
        matched_rules: list[str],
    ) -> None:
        self.gateway.telemetry.record_tool_decision(
            tenant=request.tenant,
            app=str(request.context.get("app") or request.context.get("application") or "tool-governance"),
            connector_id=request.connector_id,
            action=request.action,
            decision=decision,
            approval_required=approval_required,
            reason_codes=reason_codes,
            matched_rules=matched_rules,
        )


def serve_sidecar(
    policy_file: str | Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    tool_policy_file: str | Path | None = None,
    auth_token: str | None = None,
    policy_auth_token: str | None = None,
    policy_cache_file: str | Path | None = None,
    policy_refresh_seconds: float = 60.0,
    policy_timeout_seconds: float = 5.0,
    policy_retry_base_seconds: float = 1.0,
    policy_retry_max_seconds: float = 60.0,
    policy_retry_jitter_seconds: float = 0.25,
    fail_closed: bool = True,
    session_monitor: SessionStateMonitor | None = None,
    emergency_revoke_file: str | Path | None = None,
    policy_sha256: str | None = None,
    fallback_policy_file: str | Path | None = None,
    audit_signing_secret: str | None = None,
    policy_rollout: PolicyRollout | None = None,
) -> None:
    sidecar = PolicyAwareSidecar.from_files(
        policy_file,
        tool_policy_file,
        auth_token=auth_token,
        policy_auth_token=policy_auth_token,
        policy_cache_file=policy_cache_file,
        policy_refresh_seconds=policy_refresh_seconds,
        policy_timeout_seconds=policy_timeout_seconds,
        policy_retry_base_seconds=policy_retry_base_seconds,
        policy_retry_max_seconds=policy_retry_max_seconds,
        policy_retry_jitter_seconds=policy_retry_jitter_seconds,
        fail_closed=fail_closed,
        session_monitor=session_monitor,
        emergency_revoke_file=emergency_revoke_file,
        policy_sha256=policy_sha256,
        fallback_policy_file=fallback_policy_file,
        audit_signing_secret=audit_signing_secret,
        policy_rollout=policy_rollout,
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            self._respond(*sidecar.handle("GET", self.path, headers=_headers_dict(self.headers)))

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
            try:
                body = json.loads(raw.decode("utf-8")) if raw else {}
            except json.JSONDecodeError as exc:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "invalid_json", "detail": str(exc)})
                return
            self._respond(*sidecar.handle("POST", self.path, body, headers=_headers_dict(self.headers)))

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
            return

        def _respond(self, status: int, payload: dict[str, Any] | str) -> None:
            if isinstance(payload, str):
                data = payload.encode("utf-8")
                content_type = "text/plain; version=0.0.4; charset=utf-8"
            else:
                data = json.dumps(payload, indent=2).encode("utf-8")
                content_type = "application/json"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer((host, port), Handler)
    auth_status = "enabled" if auth_token else "disabled"
    print(f"PolicyAware sidecar listening on http://{host}:{port} auth={auth_status}")
    server.serve_forever()


def _gateway_request_from_body(body: dict[str, Any]) -> GatewayRequest:
    if "tenant" in body and "app" in body and "messages" in body:
        return GatewayRequest(**body)
    prompt = str(body.get("prompt", body.get("input", "")))
    return GatewayRequest(
        tenant=str(body.get("tenant", "default")),
        app=str(body.get("app", "policyaware-sidecar")),
        user=dict(body.get("user", {"role": "developer"})),
        context=dict(body.get("context", {"region": "us", "risk": "low", "task_type": "sidecar"})),
        messages=[{"role": "user", "content": prompt}],
        tools=list(body.get("tools", [])),
        metadata=dict(body.get("metadata", {})),
    )


def _headers_dict(headers: Any) -> dict[str, str]:
    return {str(key): str(value) for key, value in headers.items()}
