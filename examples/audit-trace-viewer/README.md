# Audit Trace Viewer

Write audit traces and generate a local HTML trace viewer for compliance review.

## Install

```bash
pip install policyaware
```

## Run

```bash
python audit_demo.py
```

Expected output:

```text
traces_written=2
viewer=.policyaware-demo/trace-viewer.html
first_decision=allow
second_decision=conditional_allow
```

See [terminal-output.txt](terminal-output.txt) for a captured run.

## What This Shows

- Every gateway request can write an audit trace.
- Traces include policy decision, matched rules, reason codes, risk, model, cost, and latency.
- `TraceViewer` creates a standalone HTML table for reviewers.
- The example writes under `.policyaware-demo/` so it is easy to delete.

