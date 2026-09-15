# MCP Policy Proxy

PolicyAware includes a first-class MCP JSON-RPC policy proxy core.

Use it when an AI client such as Claude Desktop, Cursor, LangGraph, a custom agent host, or another MCP-aware runtime connects to MCP servers with powerful capabilities such as filesystem access, Git operations, databases, or enterprise APIs.

## What It Does

The MCP Policy Proxy evaluates raw MCP JSON-RPC traffic before the MCP server executes the tool call.

It can:

- inspect `tools/call` requests,
- map MCP tool names to PolicyAware connector/action rules,
- evaluate user role, tenant, agent identity, request context, and arguments,
- deny unsafe calls before execution,
- require approval for sensitive actions,
- redact sensitive argument values before forwarding,
- return structured JSON-RPC errors for blocked calls,
- pass through non-tool MCP protocol messages such as `initialize`.

## Main APIs

| API | What It Does |
| --- | --- |
| `MCPPolicyProxy.from_policy_file(path)` | Loads MCP/tool governance YAML and creates a proxy core. |
| `proxy.evaluate(jsonrpc_request)` | Evaluates one MCP JSON-RPC request. |
| `MCPStdioPolicyProxy` | Runs a live stdio MCP proxy in front of a real MCP server command. |
| `MCPProxyResult.allowed` | Whether the request can be forwarded. |
| `MCPProxyResult.request` | Sanitized request to forward when allowed. |
| `MCPProxyResult.response` | JSON-RPC error response when blocked or approval-gated. |

## MCP JSON-RPC Input

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "filesystem.read_file",
    "arguments": {
      "path": "notes.txt",
      "query": "email jane@example.com"
    }
  }
}
```

PolicyAware maps:

- `filesystem.read_file` -> connector `filesystem`, action `read_file`
- `github/create_pr` -> connector `github`, action `create_pr`
- `read_file` with `connector_id="filesystem"` -> connector `filesystem`, action `read_file`

## YAML Policy

```yaml
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

## Python Example

```python
from policyaware import MCPPolicyProxy

proxy = MCPPolicyProxy.from_policy_file(
    "examples/policies/tool-governance.yaml",
    connector_id="github",
    agent_id="claude_desktop",
    user={"id": "u_123", "role": "developer"},
)

result = proxy.evaluate(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "README.md", "query": "email jane@example.com"},
        },
    }
)

if result.allowed:
    safe_request = result.request
    # forward safe_request to the real MCP server transport
else:
    blocked_response = result.response
    # return blocked_response to the MCP client
```

## CLI Example

Save a request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "github.delete_branch",
    "arguments": {
      "branch": "main"
    }
  }
}
```

Run:

```bash
policyaware mcp check examples/policies/tool-governance.yaml mcp-request.json
```

For a denied request, PolicyAware returns a JSON-RPC error object:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "Tool action denied by default or policy.",
    "data": {
      "blocked": true,
      "decision": "deny",
      "connector_id": "github",
      "action": "delete_branch"
    }
  }
}
```

## Live Stdio Proxy

Use `policyaware mcp proxy` when an MCP client expects to launch a local stdio MCP server command.

```bash
policyaware mcp proxy \
  examples/policies/tool-governance.yaml \
  --connector filesystem \
  --agent claude_desktop \
  --role developer \
  --server-command "python filesystem_mcp_server.py"
```

The proxy starts the real MCP server command, reads MCP JSON-RPC messages from stdin, evaluates each client request, and then either:

- forwards the sanitized request to the MCP server,
- returns a JSON-RPC policy error directly to the client, or
- passes through non-tool protocol messages.

Example MCP client configuration pattern:

```json
{
  "mcpServers": {
    "filesystem-policyaware": {
      "command": "policyaware",
      "args": [
        "mcp",
        "proxy",
        "policyaware.yaml",
        "--connector",
        "filesystem",
        "--server-command",
        "python filesystem_mcp_server.py"
      ]
    }
  }
}
```

This pattern is useful for Claude Desktop, Cursor, local agent hosts, or any MCP client that can launch a stdio server command.

For a step-by-step filesystem example, see [Secure An MCP Filesystem Server With PolicyAware](mcp-filesystem-server-tutorial.md).

## Runnable Demo

Run the local demo to see allowed, redacted, approval-gated, and denied MCP tool calls:

```bash
python examples/mcp-policy-proxy-demo/mcp_proxy_demo.py
```

From a source checkout, install the repo in editable mode first with `pip install -e .`, or run with `PYTHONPATH=src` so Python imports the local package instead of an older global install.

The demo shows PolicyAware evaluating raw MCP JSON-RPC `tools/call` requests before a filesystem, Git, database, or API MCP server would execute them.

## Transport Boundary

`MCPPolicyProxy` is transport-neutral and `MCPStdioPolicyProxy` is the built-in stdio transport wrapper. HTTP/SSE transports can reuse the same `MCPPolicyProxy.evaluate(...)` decision core.

You can embed it in:

- the built-in stdio MCP wrapper,
- a local HTTP MCP bridge,
- a Claude Desktop launcher script,
- a Cursor or coding-agent wrapper,
- a LangGraph tool node,
- an enterprise sidecar.

This keeps PolicyAware vendor-neutral while making MCP isolation first-class.

## Recommended Pattern

1. Keep MCP policy deny-by-default.
2. Use connector/action names that match real MCP server capabilities.
3. Require approval for write, delete, deploy, payment, and permission-changing actions.
4. Deny destructive commands by default.
5. Enable secret detection for MCP arguments.
6. Redact PII/PHI in allowed argument payloads before forwarding.
7. Log `MCPProxyResult` to your audit and telemetry pipeline.
