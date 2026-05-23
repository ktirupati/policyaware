# Approval Workflow Hooks

Send high-risk requests to a human approval queue instead of calling a model.

## Install

```bash
pip install policyaware
```

## Run

```bash
python approval_demo.py
```

Expected output:

```text
decision=require_approval
model_called=False
approval_file=.policyaware-demo/approvals.jsonl
approval_status=pending
```

See [terminal-output.txt](terminal-output.txt) for a captured run.

## What This Shows

- Policy can return `require_approval`.
- Gateway stops before model execution.
- `FileApprovalClient` writes a JSONL approval request.
- The same approval interface can be swapped for webhooks or enterprise workflow systems.

