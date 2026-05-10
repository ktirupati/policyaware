from __future__ import annotations

import re

from policyaware.models import DataFindings


class DataProtectionEngine:
    """Detects common sensitive data patterns and can redact them."""

    PATTERNS: dict[str, re.Pattern[str]] = {
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "phone": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
        "api_key": re.compile(r"\b(?:sk|pk|api|secret|token)_[A-Za-z0-9_\-]{16,}\b", re.I),
        "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b", re.I),
        "medical_record": re.compile(r"\b(?:MRN|medical record|patient id)[:#\s]+[A-Z0-9-]{5,}\b", re.I),
        "diagnosis": re.compile(r"\b(?:diagnosis|icd-10|prescription|medication)[:\s]", re.I),
    }

    PII = {"email", "phone", "ssn", "credit_card"}
    PHI = {"medical_record", "diagnosis"}
    SECRETS = {"api_key", "bearer_token"}

    def inspect(self, text: str) -> DataFindings:
        categories: list[str] = []
        redactions = 0
        for category, pattern in self.PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                categories.append(category)
                redactions += len(matches)

        found = set(categories)
        return DataFindings(
            contains_pii=bool(found & self.PII),
            contains_phi=bool(found & self.PHI),
            contains_secrets=bool(found & self.SECRETS),
            categories=categories,
            redactions=redactions,
        )

    def redact(self, text: str) -> DataFindings:
        findings = self.inspect(text)
        redacted = text
        for category, pattern in self.PATTERNS.items():
            redacted = pattern.sub(f"[REDACTED_{category.upper()}]", redacted)
        findings.redacted_text = redacted
        return findings

