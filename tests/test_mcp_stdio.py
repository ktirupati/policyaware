from io import BytesIO
from pathlib import Path

from policyaware import (
    MCPStdioPolicyProxy,
    MCPStdioProxyConfig,
    decode_mcp_frame,
    encode_mcp_message,
    read_mcp_message,
    write_mcp_message,
)


def _policy(path: Path) -> Path:
    policy = path / "mcp-policy.yaml"
    policy.write_text(
        """
id: mcp_stdio_policy
schema_version: "0.2"
default: deny
connectors:
  - id: filesystem
    type: mcp
    actions:
      read_file:
        effect: allow
        when:
          user.role_in: [developer]
      delete_file:
        effect: deny
""",
        encoding="utf-8",
    )
    return policy


def test_mcp_content_length_framing_round_trip() -> None:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    frame = encode_mcp_message(payload)

    assert frame.startswith(b"Content-Length:")
    assert decode_mcp_frame(frame) == payload
    assert read_mcp_message(BytesIO(frame)) == payload

    out = BytesIO()
    write_mcp_message(out, payload)
    assert decode_mcp_frame(out.getvalue()) == payload


def test_read_mcp_message_supports_newline_json() -> None:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

    assert read_mcp_message(BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')) == payload


def test_stdio_proxy_handles_allowed_and_blocked_client_messages(tmp_path: Path) -> None:
    proxy = MCPStdioPolicyProxy(
        MCPStdioProxyConfig(
            policy_file=_policy(tmp_path),
            server_command="python fake_server.py",
            connector_id="filesystem",
        )
    )

    allowed, forwarded = proxy.handle_client_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "README.md"}},
        }
    )
    blocked, response = proxy.handle_client_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "delete_file", "arguments": {"path": "prod.db"}},
        }
    )

    assert allowed is True
    assert forwarded["params"]["arguments"]["path"] == "README.md"
    assert blocked is False
    assert response["error"]["code"] == -32000
