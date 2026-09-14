from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from policyaware.integrity import IntegritySigner


class TamperEvidentAuditRecord(BaseModel):
    sequence: int
    payload: dict[str, Any]
    payload_digest: str
    previous_hash: str | None = None
    record_hash: str
    signature: str | None = None
    algorithm: str
    hardware_backed: bool = False
    notes: list[str] = Field(default_factory=list)


class TamperEvidentAuditChain:
    """Hash-chain audit evidence for append-only verification.

    The base package provides deterministic SHA256/HMAC-SHA256 chaining. Teams
    that require hardware-backed signatures can send record_hash values to a KMS,
    HSM, Nitro Enclave, or equivalent signing boundary.
    """

    def __init__(self, signer: IntegritySigner | None = None):
        self.signer = signer or IntegritySigner()
        self.records: list[TamperEvidentAuditRecord] = []

    def append(self, payload: dict[str, Any]) -> TamperEvidentAuditRecord:
        previous_hash = self.records[-1].record_hash if self.records else None
        payload_signature = self.signer.sign(payload)
        envelope = {
            "sequence": len(self.records) + 1,
            "payload_digest": payload_signature.digest,
            "previous_hash": previous_hash,
        }
        record_signature = self.signer.sign(envelope)
        record = TamperEvidentAuditRecord(
            sequence=len(self.records) + 1,
            payload=payload,
            payload_digest=payload_signature.digest,
            previous_hash=previous_hash,
            record_hash=record_signature.digest,
            signature=record_signature.signature,
            algorithm=record_signature.algorithm,
            hardware_backed=False,
            notes=[
                "Base PolicyAware audit chains are tamper-evident hash chains.",
                "Use external KMS/HSM/Nitro signing when hardware-backed attestation is required.",
            ],
        )
        self.records.append(record)
        return record

    def verify(self, records: list[TamperEvidentAuditRecord] | None = None) -> bool:
        chain = records or self.records
        previous_hash: str | None = None
        for index, record in enumerate(chain, start=1):
            if record.sequence != index:
                return False
            if record.previous_hash != previous_hash:
                return False
            payload_signature = self.signer.sign(record.payload)
            if payload_signature.digest != record.payload_digest:
                return False
            envelope = {
                "sequence": record.sequence,
                "payload_digest": record.payload_digest,
                "previous_hash": record.previous_hash,
            }
            expected = self.signer.sign(envelope)
            if expected.digest != record.record_hash:
                return False
            if record.signature and expected.signature != record.signature:
                return False
            previous_hash = record.record_hash
        return True
