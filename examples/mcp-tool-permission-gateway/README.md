# MCP Tool Permission Gateway

Govern MCP-style connector and action permissions before an agent calls a tool.

## Install

```bash
pip install policyaware
```

## Run

```bash
python tool_gateway_demo.py
```

Expected output:

```text
github.read_file as developer: allow approval_required=False
github.create_pr as developer: require_approval approval_required=True
github.delete_branch as developer: deny approval_required=False
snowflake.query medical database: deny approval_required=False
```

See [terminal-output.txt](terminal-output.txt) for a captured run.

## What This Shows

- Connector-level governance for tools such as GitHub and Snowflake.
- Action-level permissions for read, write, and delete operations.
- Human approval for sensitive write actions.
- Deny-by-default behavior for destructive or disallowed requests.

