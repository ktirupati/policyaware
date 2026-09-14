from __future__ import annotations

import re

from policyaware.models import DataFindings, SyntheticRedactionResult


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
    SYNTHETIC_VALUES = {
        "email": "alex.morgan@example.com",
        "phone": "415-555-0188",
        "ssn": "123-45-6789",
        "credit_card": "4111 1111 1111 1111",
        "api_key": "api_SYNTHETIC_KEY_DO_NOT_USE",
        "bearer_token": "Bearer SYNTHETIC_TOKEN_DO_NOT_USE",
        "medical_record": "MRN SYNTH-10001",
        "diagnosis": "diagnosis: synthetic condition",
    }

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

    def synthesize(self, text: str, *, reversible: bool = True) -> SyntheticRedactionResult:
        """Replace sensitive values with structurally useful synthetic values.

        Unlike placeholder redaction, synthetic replacement preserves formats that
        LLMs, tests, validators, and RAG prompts often depend on. The returned
        map is local-only evidence that lets callers restore original values only
        inside their trusted application boundary.
        """

        synthetic = text
        synthetic_map: dict[str, str] = {}
        categories: list[str] = []
        counters: dict[str, int] = {}

        for category, pattern in self.PATTERNS.items():
            base_value = self.SYNTHETIC_VALUES[category]

            def replacement(match: re.Match[str]) -> str:
                original = match.group(0)
                counters[category] = counters.get(category, 0) + 1
                value = _synthetic_variant(category, base_value, counters[category])
                synthetic_map[value] = original
                if category not in categories:
                    categories.append(category)
                return value

            synthetic = pattern.sub(replacement, synthetic)

        return SyntheticRedactionResult(
            original_text=text,
            synthetic_text=synthetic,
            synthetic_map=synthetic_map if reversible else {},
            categories=categories,
            reversible=reversible,
        )


def _synthetic_variant(category: str, base_value: str, index: int) -> str:
    if index == 1:
        return base_value
    if category == "email":
        return f"alex.morgan+{index}@example.com"
    if category == "phone":
        return f"415-555-{1800 + index:04d}"
    if category == "ssn":
        return f"123-45-{6789 + index:04d}"
    if category == "credit_card":
        return f"4111 1111 1111 {1111 + index:04d}"
    if category == "medical_record":
        return f"MRN SYNTH-{10000 + index}"
    return f"{base_value}_{index}"
