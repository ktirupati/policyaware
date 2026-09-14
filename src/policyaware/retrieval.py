from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field


class RetrievedDocument(BaseModel):
    content: str
    source: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RetrievalFinding(BaseModel):
    source: str | None = None
    severity: str = "medium"
    title: str
    reason: str
    pattern: str


class RetrievalGuardResult(BaseModel):
    blocked: bool
    documents: list[RetrievedDocument] = Field(default_factory=list)
    findings: list[RetrievalFinding] = Field(default_factory=list)
    redactions: int = 0


class RetrievalGuard:
    """Sanitize retrieved context before it is injected into an LLM prompt."""

    DEFAULT_PATTERNS = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"disregard\s+(the\s+)?system\s+prompt",
        r"reveal\s+(the\s+)?system\s+prompt",
        r"call\s+(the\s+)?tool",
        r"transfer\s+\$?\d+",
        r"delete\s+(all\s+)?(rows|records|database)",
        r"<[^>]+style=[\"'][^\"']*(display\s*:\s*none|visibility\s*:\s*hidden)[^\"']*[\"'][^>]*>",
        r"<!--.*?(ignore|system prompt|tool|delete|transfer).*?-->",
    ]

    def __init__(
        self,
        patterns: list[str] | None = None,
        *,
        replacement: str = "[POLICYAWARE_RETRIEVAL_REDACTED]",
        block_on_high_risk: bool = False,
    ):
        self.patterns = [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in (patterns or self.DEFAULT_PATTERNS)]
        self.replacement = replacement
        self.block_on_high_risk = block_on_high_risk

    def sanitize(self, documents: list[RetrievedDocument | dict[str, Any] | str]) -> RetrievalGuardResult:
        sanitized: list[RetrievedDocument] = []
        findings: list[RetrievalFinding] = []
        redactions = 0

        for raw in documents:
            doc = self._coerce_document(raw)
            content = doc.content
            for pattern in self.patterns:
                matches = list(pattern.finditer(content))
                if not matches:
                    continue
                redactions += len(matches)
                findings.append(
                    RetrievalFinding(
                        source=doc.source,
                        severity="high",
                        title="Indirect prompt injection pattern in retrieved context",
                        reason="Retrieved content attempted to alter model or tool behavior before prompt assembly.",
                        pattern=pattern.pattern,
                    )
                )
                content = pattern.sub(self.replacement, content)
            sanitized.append(
                RetrievedDocument(content=content, source=doc.source, metadata=dict(doc.metadata))
            )

        return RetrievalGuardResult(
            blocked=self.block_on_high_risk and bool(findings),
            documents=sanitized,
            findings=findings,
            redactions=redactions,
        )

    def _coerce_document(self, raw: RetrievedDocument | dict[str, Any] | str) -> RetrievedDocument:
        if isinstance(raw, RetrievedDocument):
            return raw
        if isinstance(raw, str):
            return RetrievedDocument(content=raw)
        return RetrievedDocument(**raw)
