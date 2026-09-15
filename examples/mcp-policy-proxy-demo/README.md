# MCP Policy Proxy Demo

This example shows PolicyAware acting as a first-class MCP JSON-RPC policy proxy.

It evaluates raw MCP `tools/call` requests before they reach a real MCP server. The proxy can:

- forward safe requests,
- redact sensitive arguments,
- require approval for write actions,
- deny destructive or disallowed actions,
- return structured JSON-RPC errors to the MCP client.

## Run

```bash
pip install -U policyaware
python mcp_proxy_demo.py
```

From a local source checkout, run `pip install -e .` once from the repository root before running the example. For a one-off source-tree run, use `PYTHONPATH=src python examples/mcp-policy-proxy-demo/mcp_proxy_demo.py`.

Expected output:

```text
SAFE READ: allowed=True action=forward decision=allow redactions=0
PII READ: allowed=True action=forward decision=allow redactions=1
CREATE PR: allowed=False action=block decision=require_approval redactions=0
DELETE BRANCH: allowed=False action=block decision=deny redactions=0
MEDICAL QUERY: allowed=False action=block decision=deny redactions=0
```

See [terminal-output.txt](terminal-output.txt) for a captured run.

## Why This Matters

MCP servers can expose broad filesystem, Git, database, and enterprise API capabilities. PolicyAware sits between the AI client and MCP server, unpacks the JSON-RPC tool call, evaluates connector/action policy, redacts sensitive arguments when allowed, and blocks unsafe calls before execution.
