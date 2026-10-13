from __future__ import annotations

import json
from pathlib import Path

from policyaware.audit import AuditLogger, SQLiteAuditLogger
from policyaware.gateway import Gateway
from policyaware.models import Decision, GatewayRequest, ToolCallRequest
from policyaware.policy import PolicyEngine
from policyaware.tools import ToolPolicyEngine, ToolRegistry


def _policy(version: str = "2026.10.1") -> dict:
    return {
        "id": "support-policy",
        "policy_version": version,
        "schema_version": "0.4",
        "default": "allow",
        "rules": [],
    }


def test_policy_decision_has_stable_policy_provenance() -> None:
    policy_a = PolicyEngine(_policy())
    policy_b = PolicyEngine(dict(reversed(list(_policy().items()))))
    policy_c = PolicyEngine(_policy("2026.10.2"))
    request = GatewayRequest(
        tenant="acme",
        app="support",
        messages=[{"role": "user", "content": "Summarize the ticket."}],
    )
    findings = Gateway.from_policy_file("examples/policies/basic.yaml").data_protection.inspect(
        request.prompt_text
    )

    decision_a = policy_a.decide(request, findings)
    decision_b = policy_b.decide(request, findings)
    decision_c = policy_c.decide(request, findings)

    assert decision_a.policy_id == "support-policy"
    assert decision_a.policy_version == "2026.10.1"
    assert decision_a.policy_schema_version == "0.4"
    assert len(decision_a.policy_sha256) == 64
    assert decision_a.policy_sha256 == decision_b.policy_sha256
    assert decision_a.policy_sha256 != decision_c.policy_sha256


def test_metadata_snapshot_omits_raw_request_and_response(tmp_path: Path) -> None:
    request_text = "private prompt unique-marker-req"
    request = GatewayRequest(
        tenant="acme",
        app="support",
        user={"id": "opaque-user"},
        context={"session_id": "opaque-session", "private": "unique-marker-context"},
        messages=[{"role": "user", "content": request_text}],
        metadata={"private": "unique-marker-metadata"},
        tools=[{"name": "lookup", "arguments": {"secret": "unique-marker-tool"}}],
    )
    gateway = Gateway(
        PolicyEngine(_policy()),
        audit_logger=AuditLogger(tmp_path / "metadata.jsonl", snapshot_mode="metadata"),
    )

    response = gateway.chat(request)
    trace = gateway.audit_logger.read_traces()[0]
    serialized = json.dumps(trace)
    response_snapshot = json.dumps(trace["response_snapshot"])

    assert response.policy.policy_sha256 == trace["policy_sha256"]
    assert response.policy.policy_version == trace["policy_version"]
    assert trace["snapshot_mode"] == "metadata"
    assert trace["request_snapshot"] == {"request_id": request.request_id}
    assert "content" not in trace["response_snapshot"]
    assert "policy" in trace["response_snapshot"]
    assert response.content not in response_snapshot
    for marker in (
        request_text,
        "unique-marker-context",
        "unique-marker-metadata",
        "unique-marker-tool",
    ):
        assert marker not in serialized


def test_full_snapshot_remains_backward_compatible(tmp_path: Path) -> None:
    request = GatewayRequest(
        tenant="acme",
        app="support",
        messages=[{"role": "user", "content": "include this prompt"}],
    )
    gateway = Gateway(
        PolicyEngine(_policy()),
        audit_logger=AuditLogger(tmp_path / "full.jsonl"),
    )

    gateway.chat(request)
    trace = gateway.audit_logger.read_traces()[0]

    assert trace["snapshot_mode"] == "full"
    assert trace["request_snapshot"]["messages"][0]["content"] == "include this prompt"
    assert "content" in trace["response_snapshot"]


def test_sqlite_logger_supports_metadata_snapshots(tmp_path: Path) -> None:
    request = GatewayRequest(
        tenant="acme",
        app="support",
        messages=[{"role": "user", "content": "private sqlite prompt"}],
    )
    gateway = Gateway(
        PolicyEngine(_policy()),
        audit_logger=SQLiteAuditLogger(tmp_path / "metadata.db", snapshot_mode="metadata"),
    )

    response = gateway.chat(request)
    trace = gateway.audit_logger.read_traces()[0]

    assert trace["snapshot_mode"] == "metadata"
    assert trace["request_snapshot"] == {"request_id": request.request_id}
    assert "private sqlite prompt" not in json.dumps(trace)
    assert response.policy.policy_sha256 == trace["policy_sha256"]


def test_tool_decision_includes_tool_policy_provenance() -> None:
    config = {
        "id": "tool-policy",
        "policy_version": "7",
        "schema_version": "0.4",
        "default": "deny",
        "connectors": [
            {"id": "files", "actions": {"read": {"effect": "allow"}}},
        ],
    }
    engine = ToolPolicyEngine(
        ToolRegistry({connector["id"]: connector for connector in config["connectors"]}),
        policy=config,
    )

    decision = engine.decide(
        ToolCallRequest(agent_id="agent", connector_id="files", action="read")
    )

    assert decision.decision == Decision.ALLOW
    assert decision.policy_id == "tool-policy"
    assert decision.policy_version == "7"
    assert len(decision.policy_sha256) == 64
