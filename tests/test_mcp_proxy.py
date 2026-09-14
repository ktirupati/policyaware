import json
from pathlib import Path

from typer.testing import CliRunner

from policyaware import MCPPolicyProxy
from policyaware.cli import app


def _policy(path: Path) -> Path:
    policy = path / "mcp-policy.yaml"
    policy.write_text(
        """
id: mcp_proxy_policy
schema_version: "0.2"
default: deny
connectors:
  - id: filesystem
    type: mcp
    actions:
      read_file:
        effect: allow
        risk: low
        side_effect: none
        when:
          user.role_in: [developer]
      write_file:
        effect: require_approval
        risk: high
        side_effect: write
        when:
          user.role_in: [developer]
      delete_file:
        effect: deny
        risk: critical
        side_effect: delete
""",
        encoding="utf-8",
    )
    return policy


def test_mcp_proxy_forwards_allowed_tool_call_and_redacts_arguments(tmp_path: Path) -> None:
    proxy = MCPPolicyProxy.from_policy_file(_policy(tmp_path), connector_id="filesystem")
    result = proxy.evaluate(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "notes.txt", "query": "email jane@example.com"},
            },
        }
    )

    assert result.allowed is True
    assert result.action == "forward"
    assert result.connector_id == "filesystem"
    assert result.redactions == 1
    assert result.request["params"]["arguments"]["query"] == "email [REDACTED_EMAIL]"


def test_mcp_proxy_blocks_denied_tool_call(tmp_path: Path) -> None:
    proxy = MCPPolicyProxy.from_policy_file(_policy(tmp_path), connector_id="filesystem")
    result = proxy.evaluate(
        {
            "jsonrpc": "2.0",
            "id": "abc",
            "method": "tools/call",
            "params": {"name": "delete_file", "arguments": {"path": "prod.db"}},
        }
    )

    assert result.allowed is False
    assert result.response["jsonrpc"] == "2.0"
    assert result.response["id"] == "abc"
    assert result.response["error"]["code"] == -32000
    assert result.response["error"]["data"]["connector_id"] == "filesystem"


def test_mcp_proxy_approval_required_returns_distinct_jsonrpc_error(tmp_path: Path) -> None:
    proxy = MCPPolicyProxy.from_policy_file(_policy(tmp_path), connector_id="filesystem")
    result = proxy.evaluate(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": "README.md"}},
        }
    )

    assert result.allowed is False
    assert result.response["error"]["code"] == -32001
    assert result.response["error"]["data"]["approval_required"] is True


def test_mcp_proxy_passes_through_non_tool_call(tmp_path: Path) -> None:
    proxy = MCPPolicyProxy.from_policy_file(_policy(tmp_path), connector_id="filesystem")
    result = proxy.evaluate({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})

    assert result.allowed is True
    assert result.action == "pass_through"
    assert result.reason_codes == ["MCP.PASSTHROUGH"]


def test_mcp_check_cli(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "filesystem.delete_file", "arguments": {"path": "prod.db"}},
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["mcp", "check", str(policy), str(request)])

    assert result.exit_code == 0
    assert '"allowed": false' in result.output
    assert "filesystem" in result.output
