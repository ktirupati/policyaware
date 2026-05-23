# Regulated RAG Assistant

Require citation-aware answers and stricter governance for regulated RAG workflows.

## Install

```bash
pip install policyaware
```

## Run

```bash
python rag_demo.py
```

Expected output:

```text
grounded_answer decision=allow citation_check=True
missing_citation decision=allow citation_check=False
phi_request decision=conditional_allow actions=redact risk=medium
```

See [terminal-output.txt](terminal-output.txt) for a captured run.

## What This Shows

- RAG requests can require citations through request context.
- Runtime evaluation flags missing citations.
- Healthcare/PHI-style prompts increase risk.
- Policy can redact sensitive content while still allowing safe RAG execution.

