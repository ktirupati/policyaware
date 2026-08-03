# PolicyAware Policy Packs

These are copy-paste starter policies for common enterprise governance profiles.

They are not legal certifications. Treat them as policy-as-code starting points and review them with your security, privacy, compliance, and legal stakeholders.

## CLI

```bash
policyaware policy packs list
policyaware policy packs show healthcare-hipaa
policyaware policy packs copy healthcare-hipaa --out policyaware.yaml
policyaware policy validate policyaware.yaml
```

## Included Packs

- `healthcare-hipaa`
- `finance`
- `eu-ai-act-high-risk`
- `soc2-ai-controls`
