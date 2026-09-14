from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from policyaware.scanner import LocalCodeScanner, ScanReport


@dataclass(frozen=True)
class PolicySuggestion:
    policy: dict
    source_report: ScanReport
    rationale: list[str] = field(default_factory=list)

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.policy, sort_keys=False)


class PolicySuggester:
    """Generate a conservative starter policy from repository scan signals."""

    def suggest(self, path: Path, *, profile: str = "baseline", scan_out: Path | None = None) -> PolicySuggestion:
        if profile not in {"baseline", "soc2", "hipaa", "gdpr"}:
            raise ValueError("profile must be one of: baseline, soc2, hipaa, gdpr")
        scan_root = path if path.is_dir() else path.parent
        report = LocalCodeScanner(workers=1).scan(
            path,
            out=scan_out or scan_root / ".policyaware" / "policy-suggest-scan.html",
        )
        categories = report.category_counts
        rules: list[dict] = [
            {
                "name": "deny_secret_leakage",
                "effect": "deny",
                "when": {"data.contains_secrets": True},
            },
            {
                "name": "require_approval_for_high_or_critical_risk",
                "effect": "require_approval",
                "when": {"risk.tier_in": ["high", "critical"]},
            },
        ]
        rationale = [
            "Started from deny-by-default policy.",
            "Added secret-blocking and high-risk approval baseline.",
        ]

        if categories["PII"] or profile in {"gdpr", "soc2"}:
            rules.append(
                {
                    "name": "synthetic_redact_pii_for_standard_users",
                    "effect": "transform",
                    "action": "synthetic_redact",
                    "when": {
                        "data.contains_pii": True,
                        "user.role_not_in": ["privacy_admin", "compliance_officer"],
                    },
                }
            )
            rationale.append("PII signals detected or privacy profile selected; added synthetic redaction.")

        if categories["PHI"] or profile == "hipaa":
            rules.append(
                {
                    "name": "require_approval_for_phi",
                    "effect": "require_approval",
                    "when": {"data.contains_phi": True},
                }
            )
            rationale.append("PHI/healthcare signal detected or HIPAA profile selected; added approval.")

        if categories["Agent Tool Governance"] or categories["Tool Governance"]:
            rules.extend(
                [
                    {
                        "name": "require_approval_for_side_effecting_tools",
                        "effect": "require_approval",
                        "when": {
                            "request.action_type_in": [
                                "write",
                                "delete",
                                "deploy",
                                "payment",
                                "refund",
                                "permission_change",
                            ]
                        },
                    },
                    {
                        "name": "safe_rewrite_risky_tool_trajectory",
                        "effect": "transform",
                        "action": "safe_rewrite",
                        "when": {
                            "request.action_type_in": ["delete", "deploy", "payment", "refund"]
                        },
                    },
                ]
            )
            rationale.append("Tool/agent signals detected; added approval and safe rewrite controls.")

        if categories["Cost Governance"] or categories["Autonomous Agent Governance"]:
            rules.extend(
                [
                    {
                        "name": "deny_excessive_token_budget",
                        "effect": "deny",
                        "when": {"request.max_tokens_gte": 8193},
                    },
                    {
                        "name": "require_approval_for_long_agent_loops",
                        "effect": "require_approval",
                        "when": {"request.max_iterations_gte": 11},
                    },
                ]
            )
            rationale.append("Agent/cost signals detected; added token and iteration caps.")

        if categories["Provider Governance"] or categories["Data Residency"]:
            rules.append(
                {
                    "name": "require_approved_regions",
                    "effect": "deny",
                    "when": {"request.region_not_in": ["us", "eu"]},
                }
            )
            rationale.append("Provider/region signals detected; added approved-region constraint.")

        rules.append(
            {
                "name": "allow_low_medium_risk_enterprise_users",
                "effect": "allow",
                "when": {
                    "user.role_in": [
                        "developer",
                        "analyst",
                        "support_agent",
                        "platform_engineer",
                        "privacy_admin",
                        "compliance_officer",
                    ],
                    "risk.tier_in": ["low", "medium"],
                },
            }
        )

        return PolicySuggestion(
            policy={
                "id": f"policyaware_suggested_{profile}",
                "schema_version": "0.4",
                "default": "deny",
                "rules": rules,
            },
            source_report=report,
            rationale=rationale,
        )
