# Contributing

Thanks for helping build PolicyAware AI Gateway.

## Local Setup

```bash
pip install -e ".[dev]"
pytest
policyaware dev simulate
```

## Design Principles

- Deny by default.
- Keep policy decisions explainable.
- Treat tools as privileged operations.
- Keep provider integrations behind stable interfaces.
- Prefer structured traces over plain logs.
- Make local development possible without external model credentials.

## Good First Areas

- Provider adapters.
- Additional sensitive-data detectors.
- OpenTelemetry exporter.
- FastAPI request-body inspection.
- Golden dataset execution.
- Dashboard prototype.
