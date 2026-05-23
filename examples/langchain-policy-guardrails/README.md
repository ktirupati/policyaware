# LangChain Policy Guardrails

Add policy guardrails around a LangChain-style LLM call before prompts reach a model.

This example uses PolicyAware's lightweight LangChain-compatible wrapper, so it runs without installing LangChain or using an external model key.

## Install

```bash
pip install policyaware
```

## Run

```bash
python chain_demo.py
```

Expected output:

```text
safe_prompt: model_called=True decision=allow
pii_prompt: model_called=True decision=conditional_allow actions=redact
secret_prompt: model_called=False decision=deny
```

See [terminal-output.txt](terminal-output.txt) for a captured run.

## What This Shows

- A chain invokes PolicyAware before model execution.
- PII can be redacted through YAML policy.
- Secrets are denied before reaching the model.
- The same pattern can wrap a real LangChain model or runnable.

