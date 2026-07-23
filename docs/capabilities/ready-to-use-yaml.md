# Ready-To-Use YAML Policies

This page contains complete YAML files users can copy, save, and test immediately.

## How To Test A Policy

Save any core policy as a `.yaml` file, then run:

```bash
policyaware policy validate policy.yaml
policyaware policy explain policy.yaml --prompt "Email jane@example.com about the ticket."
```

For Python:

```python
from policyaware import Gateway

gateway = Gateway.from_policy_file("policy.yaml")
```

## Guardrails Section

Policies may include an optional top-level `guards` section. This lets teams run NeMo Guardrails, Guardrails AI, or custom validators as policy-as-code.

```yaml
guards:
  input:
    - name: nemo
      config_path: rails/
      when:
        request.task_type: chatbot

  output:
    - name: guardrails_ai
      rail_spec: guardrails/spec.rail
      when:
        request.output_format: json
```

Known guard names are `nemo`, `nemoguardrails`, `guardrails_ai`, `guardrails-ai`, and `guardrails`.

## 1. Basic Enterprise Policy

Save as `basic-enterprise.yaml`.

```yaml
id: basic_enterprise_policy
schema_version: "0.2"
default: deny

rules:
  - name: deny_secret_leakage
    effect: deny
    when:
      data.contains_secrets: true

  - name: redact_pii_for_standard_users
    effect: transform
    action: redact
    when:
      data.contains_pii: true
      user.role_not_in:
        - privacy_admin
        - compliance_officer

  - name: allow_enterprise_users_low_medium_risk
    effect: allow
    when:
      user.role_in:
        - support_agent
        - support_manager
        - developer
        - analyst
        - privacy_admin
      request.region: us
      risk.tier_in:
        - low
        - medium

  - name: require_approval_for_high_or_critical_risk
    effect: require_approval
    when:
      risk.tier_in:
        - high
        - critical
```

## 2. Customer Support Copilot Policy

Save as `support-copilot.yaml`.

```yaml
id: support_copilot_policy
schema_version: "0.2"
default: deny

rules:
  - name: deny_secrets
    effect: deny
    when:
      data.contains_secrets: true

  - name: redact_customer_pii
    effect: transform
    action: redact
    when:
      data.contains_pii: true
      user.role_not_in:
        - support_manager
        - privacy_admin

  - name: allow_support_summary_and_response
    effect: allow
    when:
      user.role_in:
        - support_agent
        - support_manager
      request.task_type_in:
        - support_summary
        - customer_response
      request.region: us
      request.risk_in:
        - low
        - medium

  - name: require_manager_approval_for_high_risk_support
    effect: require_approval
    when:
      request.task_type: customer_response
      risk.tier_in:
        - high
        - critical
```

## 3. Healthcare / PHI Policy

Save as `healthcare-rag.yaml`.

```yaml
id: healthcare_rag_policy
schema_version: "0.2"
default: deny

rules:
  - name: deny_secret_leakage
    effect: deny
    when:
      data.contains_secrets: true

  - name: deny_phi_outside_us
    effect: deny
    when:
      data.contains_phi: true
      request.region_not_in:
        - us

  - name: redact_phi_for_non_privileged_users
    effect: transform
    action: redact
    when:
      data.contains_phi: true
      user.role_not_in:
        - clinician
        - privacy_admin
        - compliance_officer

  - name: redact_pii_for_non_privileged_users
    effect: transform
    action: redact
    when:
      data.contains_pii: true
      user.role_not_in:
        - clinician
        - privacy_admin
        - compliance_officer

  - name: allow_clinical_rag_low_medium_risk
    effect: allow
    when:
      request.domain: healthcare
      request.task_type: rag_answer
      request.region: us
      user.role_in:
        - clinician
        - care_manager
        - compliance_officer
      risk.tier_in:
        - low
        - medium

  - name: require_approval_for_high_risk_healthcare
    effect: require_approval
    when:
      request.domain: healthcare
      risk.tier_in:
        - high
        - critical
```

## 4. Code Assistant Policy

Save as `code-assistant.yaml`.

```yaml
id: code_assistant_policy
schema_version: "0.2"
default: deny

rules:
  - name: deny_api_keys_and_tokens
    effect: deny
    when:
      data.contains_secrets: true

  - name: allow_low_medium_risk_code_tasks
    effect: allow
    when:
      user.role_in:
        - developer
        - maintainer
        - security_reviewer
      request.task_type_in:
        - code_review
        - code_generation
        - documentation
      request.region: us
      request.risk_in:
        - low
        - medium

  - name: require_approval_for_deploy_or_delete
    effect: require_approval
    when:
      request.action_type_in:
        - deploy
        - delete
        - permission_change

  - name: require_approval_for_high_risk_code
    effect: require_approval
    when:
      risk.tier_in:
        - high
        - critical
```

## 5. ML-Assisted Governance Policy

Save as `ml-governance.yaml`.

Use this with optional ML classifiers such as Presidio, ProtectAI, or a custom Transformers classifier.

```yaml
id: ml_assisted_governance_policy
schema_version: "0.2"
default: deny

rules:
  - name: deny_prompt_injection
    effect: deny
    when:
      ml.prompt_injection.detected: true

  - name: require_approval_for_possible_injection
    effect: require_approval
    when:
      ml.prompt_injection.score_gte: 0.7

  - name: require_approval_for_high_confidence_pii
    effect: require_approval
    when:
      ml.pii.detected: true
      ml.pii.score_gte: 0.85

  - name: require_approval_for_regulated_domain
    effect: require_approval
    when:
      ml.domain.label_in:
        - healthcare
        - finance
        - legal
        - hr
      risk.tier_in:
        - medium
        - high
        - critical

  - name: redact_builtin_pii
    effect: transform
    action: redact
    when:
      data.contains_pii: true

  - name: allow_public_safe_requests
    effect: allow
    when:
      ml.domain.label: public-safe
      data.contains_sensitive: false
      risk.tier_in:
        - low
        - medium
```

## 6. Agent Tool Governance Policy

Save as `tool-governance.yaml`.

This file is used with:

```bash
policyaware tools check tool-governance.yaml --agent code_assistant --connector github --action create_pr --role developer
```

```yaml
id: agent_tool_governance
schema_version: "0.2"
default: deny

connectors:
  - id: github
    type: mcp
    risk: medium
    actions:
      read_file:
        effect: allow
        risk: low
        side_effect: none
        when:
          user.role_in:
            - developer
            - maintainer
            - security_reviewer
        limits:
          calls_per_minute: 60

      create_pr:
        effect: require_approval
        risk: high
        side_effect: write
        when:
          user.role_in:
            - developer
            - maintainer

      write_file:
        effect: require_approval
        risk: high
        side_effect: write
        when:
          user.role_in:
            - developer
            - maintainer

      delete_branch:
        effect: deny
        risk: critical
        side_effect: delete

  - id: snowflake
    type: mcp
    risk: high
    actions:
      query:
        effect: allow
        risk: medium
        side_effect: read
        when:
          user.role_in:
            - analyst
            - data_scientist
          arguments.database_not_in:
            - payroll
            - medical
        limits:
          calls_per_hour: 20
          max_rows: 1000
```

## 7. Golden Evaluation Suite

Save as `governance-eval.yaml`.

```yaml
suite: governance_policy_eval

checks:
  - type: expected_policy_decision
  - type: expected_reason_codes
  - type: sensitive_data_leakage

cases:
  - id: support_ticket_allowed
    input: "Summarize this customer request."
    user:
      id: eval_user
      role: support_agent
    context:
      region: us
      risk: low
      task_type: support
    expected:
      decision: allow
      reason_codes:
        - POLICY.ALLOW_MATCHED

  - id: pii_is_redacted
    input: "Email jane@example.com about the claim."
    user:
      id: eval_user
      role: support_agent
    context:
      region: us
      risk: low
      task_type: support
    expected:
      decision: conditional_allow
      reason_codes:
        - DATA.PII_DETECTED
        - POLICY.TRANSFORM_APPLIED

  - id: secret_is_denied
    input: "Use secret_api_key_abcdefghijklmnop in the deployment."
    user:
      id: eval_user
      role: developer
    context:
      region: us
      risk: low
      task_type: code_assistant
    expected:
      decision: deny
      reason_codes:
        - DATA.SECRET_DETECTED
        - POLICY.DENY_MATCHED
```

Run:

```bash
policyaware eval run governance-eval.yaml --policy-file basic-enterprise.yaml
```

## 8. Provider Routing Configuration

Save as `routing.yaml`.

This is an application routing config, not a core policy file. Load it into `ModelRouter` from Python.

```yaml
models:
  - name: local/sim-small
    provider: local
    region: us
    capabilities:
      - text
    cost_per_1k_tokens: 0.0
    quality_score: 0.7

  - name: azure/gpt-approved
    provider: azure-openai
    region: us
    capabilities:
      - text
    cost_per_1k_tokens: 0.02
    quality_score: 0.95
    metadata:
      deployment: your-azure-deployment-name

  - name: anthropic/claude-approved
    provider: anthropic
    region: us
    capabilities:
      - text
    cost_per_1k_tokens: 0.03
    quality_score: 0.95
    metadata:
      provider_model: claude-3-5-sonnet-latest

  - name: ollama/llama3.2
    provider: ollama
    region: us
    capabilities:
      - text
    cost_per_1k_tokens: 0.0
    quality_score: 0.75
    metadata:
      provider_model: llama3.2
```

Python loader:

```python
import yaml
from policyaware import ModelCandidate, ModelRouter

with open("routing.yaml", "r", encoding="utf-8") as handle:
    config = yaml.safe_load(handle)

router = ModelRouter([ModelCandidate(**item) for item in config["models"]])
```
