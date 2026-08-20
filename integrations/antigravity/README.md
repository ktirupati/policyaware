# PolicyAware Plugin for Antigravity

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)
[![PyPI](https://img.shields.io/pypi/v/policyaware.svg)](https://pypi.org/project/policyaware/)
[![Documentation](https://img.shields.io/badge/docs-github.io-green.svg)](https://ktirupati.github.io/policyaware/)

**PolicyAware** is an AI governance control plane, AI firewall, and offline repository scanner for LLM applications, RAG systems, MCP tools, and autonomous AI agents.

This plugin packages PolicyAware skills, rules, and AI governance workflows natively for **Google Antigravity**.

---

## Features

- **Offline AI Governance Scanning:** Run `policyaware scan .` to audit LLM calls, PII/PHI leakage risks, MCP tool permissions, prompt hygiene, and model routing.
- **Policy-as-Code Generation:** Generate and validate `policyaware.yaml` policies with deny-by-default rules.
- **CI/CD Protection:** Scaffold GitHub Actions scan workflows for continuous PR protection.
- **Framework Integration Guidance:** Best-practice recommendations for FastAPI, Flask, LangChain, LangGraph, LlamaIndex, Haystack, MCP tools, and sidecars.

---

## Installation & Distribution

### Local Plugin Install

This folder is a native-style Antigravity plugin package candidate. If your Antigravity CLI is available, install it from the local folder or from a checked-out copy of this repository.

Example local install:

```bash
agy plugin install ./integrations/antigravity
```

Marketplace or registry installation by name, such as `agy plugin install policyaware`, should only be documented after the plugin is accepted into an official or community Antigravity registry.

### Manual Installation (Workspace)
To enable for a specific repository, copy or symlink this folder into `.agents/plugins/policyaware/`:

```bash
mkdir -p .agents/plugins
cp -r integrations/antigravity .agents/plugins/policyaware
```

### Manual Installation (Global)
To enable globally for all Antigravity sessions on your machine:

```bash
# Linux / macOS
cp -r integrations/antigravity ~/.gemini/config/plugins/policyaware

# Windows PowerShell
Copy-Item -Recurse integrations\antigravity ~\.gemini\config\plugins\policyaware
```

---

## Quick Start Prompts

Once installed, trigger PolicyAware inside any Antigravity session using natural language:

- *"Scan this repo with PolicyAware for AI governance, PII leaks, and MCP tool risks."*
- *"Create a starter policyaware.yaml with deny-by-default rules."*
- *"Add a PolicyAware GitHub Actions workflow to scan PRs."*
- *"Recommend PolicyAware integration components for our LangChain / FastAPI app."*

---

## Plugin Directory Structure

```text
policyaware/
├── plugin.json                              # Antigravity plugin manifest
├── README.md                                # Documentation & usage
├── assets/
│   └── policyaware-icon.svg                 # PolicyAware shield logo
├── rules/
│   └── ai-governance.md                     # Model-decision AI governance guidelines
└── skills/
    └── policyaware-governance/
        └── SKILL.md                         # Full PolicyAware skill instructions
```

---

## Links

- **GitHub Repository:** [https://github.com/ktirupati/policyaware](https://github.com/ktirupati/policyaware)
- **PyPI Package:** [https://pypi.org/project/policyaware/](https://pypi.org/project/policyaware/)
- **Documentation:** [https://ktirupati.github.io/policyaware/](https://ktirupati.github.io/policyaware/)
- **Local Scan Guide:** [https://github.com/ktirupati/policyaware/blob/main/docs/local-code-scan.md](https://github.com/ktirupati/policyaware/blob/main/docs/local-code-scan.md)
