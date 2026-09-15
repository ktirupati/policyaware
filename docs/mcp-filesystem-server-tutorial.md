# Secure An MCP Filesystem Server With PolicyAware

This tutorial shows how to put PolicyAware in front of a filesystem-style MCP server so raw JSON-RPC tool calls are checked before the server touches local files.

Use this pattern for Claude Desktop, Cursor, LangGraph, custom agent hosts, or any MCP-aware runtime that launches a local stdio server command.

## What You Will Build

```text
MCP client
  -> PolicyAware MCP stdio proxy
  -> filesystem MCP server
  -> local files
```

PolicyAware evaluates every `tools/call` request before forwarding it to the real MCP server.

## 1. Install

```bash
pip install policyaware
```

## 2. Create A Deny-By-Default MCP Policy

Save this as `filesystem-policy.yaml`:

```yaml
id: filesystem_mcp_policy
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
          user.role_in: [developer, security_engineer]

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
```

Validate it:

```bash
policyaware policy validate filesystem-policy.yaml
```

## 3. Test A Raw JSON-RPC Request

Save this as `mcp-delete-request.json`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "filesystem.delete_file",
    "arguments": {
      "path": "important.txt"
    }
  }
}
```

Run:

```bash
policyaware mcp check filesystem-policy.yaml mcp-delete-request.json
```

Expected result: PolicyAware returns a JSON-RPC policy error instead of allowing the delete action through.

## 4. Run The Stdio Proxy

When you have a real filesystem MCP server command, launch it through PolicyAware:

```bash
policyaware mcp proxy \
  filesystem-policy.yaml \
  --connector filesystem \
  --agent claude_desktop \
  --role developer \
  --server-command "python filesystem_mcp_server.py"
```

The proxy starts the real MCP server command, reads MCP JSON-RPC messages from stdin, evaluates each request, and either:

- forwards the sanitized request to the MCP server,
- returns an approval-required JSON-RPC error,
- returns a deny JSON-RPC error,
- passes through non-tool MCP protocol messages.

## 5. MCP Client Configuration Pattern

For clients that launch stdio MCP servers from JSON configuration, use this pattern:

```json
{
  "mcpServers": {
    "filesystem-policyaware": {
      "command": "policyaware",
      "args": [
        "mcp",
        "proxy",
        "filesystem-policy.yaml",
        "--connector",
        "filesystem",
        "--agent",
        "claude_desktop",
        "--role",
        "developer",
        "--server-command",
        "python filesystem_mcp_server.py"
      ]
    }
  }
}
```

Adjust `--server-command` to match your actual MCP filesystem server.

## 6. What To Log

For production use, record:

- MCP request ID
- connector ID
- action name
- user role
- decision
- reason codes
- matched rules
- redaction count
- JSON-RPC error code for blocked calls

## 7. Production Checklist

- Keep policy deny-by-default.
- Deny destructive filesystem actions unless there is a very narrow approved use case.
- Require approval for writes.
- Redact PII/PHI/secrets in allowed arguments.
- Use a filesystem allowlist inside the MCP server itself.
- Run the MCP server with least-privilege OS permissions.
- Pair PolicyAware with process/container isolation for untrusted tool execution.

## Related

- [MCP Policy Proxy](mcp-policy-proxy.md)
- [MCP Tool Permission Gateway](use-cases/mcp-tool-permission-gateway.md)
- [Production Checklist](production-checklist.md)
- [Security Boundaries](security-boundaries.md)

