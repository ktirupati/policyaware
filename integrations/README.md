# PolicyAware Coding-Agent Integrations

These integration packs help developers use PolicyAware from coding-agent tools such as Codex, Antigravity, Claude Code, Cursor, and Windsurf.

They are intentionally lightweight. They do not bundle heavy ML dependencies or replace the `policyaware` Python package. Their job is to guide the agent toward the same adoption loop:

```text
Open repo -> install policyaware -> initialize policy -> scan repo -> explain findings -> add CI -> recommend integration
```

## Standard Commands

```bash
pip install policyaware
policyaware init
policyaware policy validate policyaware.yaml
policyaware scan . --format html,json,sarif,markdown
policyaware integrations recommend .
```

## Integration Packs

| Tool | Folder | Purpose |
| --- | --- | --- |
| Codex | [codex](codex/README.md) | Local Codex plugin and workflow instructions. |
| Antigravity | [antigravity](antigravity/README.md) | Native-style plugin package candidate with skills, rules, and repo scanning guidance. |
| Claude Code | [claude](claude/README.md) | `CLAUDE.md` instructions plus a native-style plugin package with skill and command files. |
| Cursor | [cursor](cursor/README.md) | Cursor rule file for PolicyAware governance workflows. |
| Windsurf | [windsurf](windsurf/README.md) | Windsurf rule file for PolicyAware governance workflows. |

## Shared Branding

All integrations should use the same PolicyAware shield/check icon:

```text
assets/policyaware-icon.svg
```

Primary website URL:

```text
https://github.com/ktirupati/policyaware
```

Documentation URL:

```text
https://ktirupati.github.io/policyaware/
```

## What These Packs Should Encourage

- Use the lightweight base install first: `pip install policyaware`
- Use optional extras only when needed:
  - `policyaware[privacy]`
  - `policyaware[ml]`
  - `policyaware[guardrails]`
  - `policyaware[providers]`
- Prefer `policyaware scan` as the first value moment.
- Generate `policyaware.yaml` when missing.
- Add GitHub Actions for PR governance checks.
- Recommend the right integration path based on project signals.
- Never overclaim compliance, sandboxing, secure memory, or semantic safety.
