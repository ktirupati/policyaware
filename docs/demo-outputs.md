# Demo Outputs

These runnable examples include captured terminal output so developers can verify behavior before connecting real models or enterprise systems.

## FastAPI LLM Policy Middleware

Folder: [examples/fastapi-llm-policy-middleware](../examples/fastapi-llm-policy-middleware)

```bash
cd examples/fastapi-llm-policy-middleware
python demo.py
```

Captured output: [terminal-output.txt](../examples/fastapi-llm-policy-middleware/terminal-output.txt)

```text
allowed_support_request: allow
pii_redaction_request: conditional_allow
secret_leak_request: deny
```

## LangChain Policy Guardrails

Folder: [examples/langchain-policy-guardrails](../examples/langchain-policy-guardrails)

```bash
cd examples/langchain-policy-guardrails
python chain_demo.py
```

Captured output: [terminal-output.txt](../examples/langchain-policy-guardrails/terminal-output.txt)

```text
safe_prompt: model_called=True decision=allow
pii_prompt: model_called=True decision=conditional_allow actions=redact
secret_prompt: model_called=False decision=deny
```

## MCP Tool Permission Gateway

Folder: [examples/mcp-tool-permission-gateway](../examples/mcp-tool-permission-gateway)

```bash
cd examples/mcp-tool-permission-gateway
python tool_gateway_demo.py
```

Captured output: [terminal-output.txt](../examples/mcp-tool-permission-gateway/terminal-output.txt)

```text
github.read_file as developer: allow approval_required=False
github.create_pr as developer: require_approval approval_required=True
github.delete_branch as developer: deny approval_required=False
snowflake.query medical database: deny approval_required=False
```

## PII Redaction Policy

Folder: [examples/pii-redaction-policy](../examples/pii-redaction-policy)

```bash
cd examples/pii-redaction-policy
python demo.py
```

Captured output: [terminal-output.txt](../examples/pii-redaction-policy/terminal-output.txt)

```text
contains_pii=True
categories=email, phone
redacted=Contact [REDACTED_EMAIL] or [REDACTED_PHONE] about claim ACME-42.
gateway_decision=conditional_allow
gateway_actions=redact
```

## Provider Routing By Risk

Folder: [examples/provider-routing-by-risk](../examples/provider-routing-by-risk)

```bash
cd examples/provider-routing-by-risk
python routing_demo.py
```

Captured output: [terminal-output.txt](../examples/provider-routing-by-risk/terminal-output.txt)

## Regulated RAG Assistant

Folder: [examples/regulated-rag-assistant](../examples/regulated-rag-assistant)

```bash
cd examples/regulated-rag-assistant
python rag_demo.py
```

Captured output: [terminal-output.txt](../examples/regulated-rag-assistant/terminal-output.txt)

## Audit Trace Viewer

Folder: [examples/audit-trace-viewer](../examples/audit-trace-viewer)

```bash
cd examples/audit-trace-viewer
python audit_demo.py
```

Captured output: [terminal-output.txt](../examples/audit-trace-viewer/terminal-output.txt)

## Approval Workflow Hooks

Folder: [examples/approval-workflow-hooks](../examples/approval-workflow-hooks)

```bash
cd examples/approval-workflow-hooks
python approval_demo.py
```

Captured output: [terminal-output.txt](../examples/approval-workflow-hooks/terminal-output.txt)

## Optional GIFs Or Screenshots

The terminal-output files are intentionally small and reviewable in Git. For launch posts or README media, record short GIFs from these exact commands so the visual demo matches the committed examples.
