# Policy Packs

PolicyAware includes bundled starter policy packs so teams do not have to begin with a blank YAML file.

These packs are policy-as-code starting points, not legal certifications. Review them with your security, privacy, compliance, and legal stakeholders before production use.

## List Packs

```bash
policyaware policy packs list
policyaware policy packs list --json
```

## Copy A Pack

```bash
policyaware policy packs copy healthcare-hipaa --out policyaware.yaml
policyaware policy validate policyaware.yaml
```

Show a pack without writing a file:

```bash
policyaware policy packs show soc2-ai-controls
```

## Included Packs

| Pack | Use When |
| --- | --- |
| `healthcare-hipaa` | Healthcare workflows need PHI/PII handling, US-region controls, and approval for high-risk requests. |
| `finance` | Financial workflows need PII redaction, money-movement approval, and stricter high-risk controls. |
| `eu-ai-act-high-risk` | EU high-risk AI workflows need personal-data redaction, human oversight, and regulated-domain review. |
| `soc2-ai-controls` | Internal AI systems need controls around secrets, PII, production changes, approvals, and evidence. |

## Python API

```python
from policyaware import copy_policy_pack, list_policy_packs, read_policy_pack

for pack in list_policy_packs():
    print(pack.id, pack.description)

yaml_text = read_policy_pack("healthcare-hipaa")
copy_policy_pack("healthcare-hipaa", "policyaware.yaml")
```

## Recommended Workflow

1. Copy the closest policy pack.
2. Validate the YAML.
3. Adapt roles, tenants, regions, actions, and domains to your environment.
4. Add tests for expected allow, deny, redact, and approval paths.
5. Review with compliance/legal stakeholders before production use.
