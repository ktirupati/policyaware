from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path


@dataclass(frozen=True)
class PolicyPack:
    id: str
    filename: str
    description: str
    compliance_note: str


POLICY_PACKS = {
    "healthcare-hipaa": PolicyPack(
        id="healthcare-hipaa",
        filename="healthcare-hipaa.yaml",
        description="Healthcare starter controls for PHI/PII redaction, US-region workflows, and high-risk approval.",
        compliance_note="HIPAA-aligned starter template; not legal certification.",
    ),
    "finance": PolicyPack(
        id="finance",
        filename="finance.yaml",
        description="Finance starter controls for PII redaction, money-movement approvals, and regulated operations.",
        compliance_note="Financial-services starter template; review against your policies and jurisdictions.",
    ),
    "eu-ai-act-high-risk": PolicyPack(
        id="eu-ai-act-high-risk",
        filename="eu-ai-act-high-risk.yaml",
        description="EU high-risk AI starter controls for personal data, human oversight, and regulated domains.",
        compliance_note="EU AI Act-oriented starter template; requires legal and risk review.",
    ),
    "soc2-ai-controls": PolicyPack(
        id="soc2-ai-controls",
        filename="soc2-ai-controls.yaml",
        description="SOC 2-oriented AI controls for secrets, PII, production changes, and evidence workflows.",
        compliance_note="SOC 2 control-support starter template; auditors must review actual controls.",
    ),
}


def list_policy_packs() -> list[PolicyPack]:
    return list(POLICY_PACKS.values())


def get_policy_pack(pack_id: str) -> PolicyPack:
    normalized = pack_id.strip().lower()
    if normalized not in POLICY_PACKS:
        known = ", ".join(sorted(POLICY_PACKS))
        raise KeyError(f"Unknown policy pack '{pack_id}'. Available packs: {known}.")
    return POLICY_PACKS[normalized]


def read_policy_pack(pack_id: str) -> str:
    pack = get_policy_pack(pack_id)
    return resources.files("policyaware.policy_packs").joinpath(pack.filename).read_text(encoding="utf-8")


def copy_policy_pack(pack_id: str, out: str | Path, *, force: bool = False) -> Path:
    output = Path(out)
    if output.exists() and not force:
        raise FileExistsError(f"Refusing to overwrite existing file: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(read_policy_pack(pack_id), encoding="utf-8")
    return output
