from __future__ import annotations

import json
import shlex
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from policyaware.mcp_proxy import MCPPolicyProxy


def encode_mcp_message(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    return b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body


def decode_mcp_frame(frame: bytes) -> dict[str, Any]:
    if b"\r\n\r\n" in frame:
        _, body = frame.split(b"\r\n\r\n", 1)
        return json.loads(body.decode("utf-8"))
    return json.loads(frame.decode("utf-8"))


def read_mcp_message(stream: BinaryIO) -> dict[str, Any] | None:
    first = stream.readline()
    if not first:
        return None

    stripped = first.strip()
    if stripped.startswith(b"{"):
        return json.loads(stripped.decode("utf-8"))

    headers = [first]
    while True:
        line = stream.readline()
        if not line:
            return None
        headers.append(line)
        if line in {b"\r\n", b"\n"}:
            break

    content_length: int | None = None
    for header in headers:
        if header.lower().startswith(b"content-length:"):
            content_length = int(header.split(b":", 1)[1].strip())
            break
    if content_length is None:
        raise ValueError("MCP stdio message missing Content-Length header.")

    body = stream.read(content_length)
    if len(body) != content_length:
        raise EOFError("MCP stdio stream ended before full message body was read.")
    return json.loads(body.decode("utf-8"))


def write_mcp_message(stream: BinaryIO, payload: dict[str, Any]) -> None:
    stream.write(encode_mcp_message(payload))
    stream.flush()


@dataclass
class MCPStdioProxyConfig:
    policy_file: Path
    server_command: str
    connector_id: str | None = None
    agent_id: str = "mcp_client"
    user_role: str = "developer"
    deny_on_secrets: bool = True


class MCPStdioPolicyProxy:
    """Live stdio transport proxy for MCP servers."""

    def __init__(self, config: MCPStdioProxyConfig):
        self.config = config
        self.policy_proxy = MCPPolicyProxy.from_policy_file(
            config.policy_file,
            connector_id=config.connector_id,
            agent_id=config.agent_id,
            user={"id": "mcp_stdio_user", "role": config.user_role},
            deny_on_secrets=config.deny_on_secrets,
        )

    def handle_client_message(self, payload: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        result = self.policy_proxy.evaluate(payload)
        if result.allowed:
            return True, result.request or payload
        return False, result.response or self._generic_error(payload, "MCP request blocked by PolicyAware.")

    def run(self) -> int:
        command = shlex.split(self.config.server_command, posix=False)
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("Unable to open MCP server stdio pipes.")

        server_to_client = threading.Thread(
            target=self._pump_server_to_client,
            args=(process.stdout, sys.stdout.buffer),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=self._pump_stderr,
            args=(process.stderr,),
            daemon=True,
        )
        server_to_client.start()
        stderr_thread.start()

        try:
            while True:
                payload = read_mcp_message(sys.stdin.buffer)
                if payload is None:
                    break
                forward, message = self.handle_client_message(payload)
                if forward:
                    write_mcp_message(process.stdin, message)
                else:
                    write_mcp_message(sys.stdout.buffer, message)
        finally:
            try:
                process.stdin.close()
            except Exception:
                pass
        return process.wait()

    def _pump_server_to_client(self, source: BinaryIO, destination: BinaryIO) -> None:
        while True:
            payload = read_mcp_message(source)
            if payload is None:
                break
            write_mcp_message(destination, payload)

    def _pump_stderr(self, source: BinaryIO | None) -> None:
        if source is None:
            return
        for line in iter(source.readline, b""):
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    def _generic_error(self, payload: dict[str, Any], message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": payload.get("id"),
            "error": {
                "code": -32000,
                "message": message,
                "data": {"blocked": True},
            },
        }
