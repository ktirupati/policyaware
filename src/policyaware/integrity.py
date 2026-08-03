from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class IntegritySignature:
    algorithm: str
    digest: str
    signature: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "digest": self.digest,
            "signature": self.signature,
        }


class IntegritySigner:
    """Create deterministic hashes and optional HMAC signatures for evidence artifacts."""

    def __init__(self, secret: str | bytes | None = None):
        self.secret = secret.encode("utf-8") if isinstance(secret, str) else secret

    def sign(self, payload: Any) -> IntegritySignature:
        canonical = canonical_json(payload)
        digest = hashlib.sha256(canonical).hexdigest()
        signature = (
            hmac.new(self.secret, canonical, hashlib.sha256).hexdigest() if self.secret else None
        )
        return IntegritySignature(
            algorithm="HMAC-SHA256" if self.secret else "SHA256",
            digest=digest,
            signature=signature,
        )

    def verify(self, payload: Any, signature: IntegritySignature | dict[str, Any]) -> bool:
        expected = signature if isinstance(signature, IntegritySignature) else IntegritySignature(**signature)
        actual = self.sign(payload)
        if not hmac.compare_digest(actual.digest, expected.digest):
            return False
        if expected.signature is None:
            return actual.signature is None
        return actual.signature is not None and hmac.compare_digest(
            actual.signature,
            expected.signature,
        )


def canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")

