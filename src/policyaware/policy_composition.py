from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

from policyaware.policy import PolicyEngine


PolicyLayerLevel = Literal[
    "emergency",
    "global",
    "compliance",
    "region",
    "tenant",
    "app",
    "local_override",
]


LAYER_PRECEDENCE: dict[str, int] = {
    "emergency": 0,
    "global": 10,
    "compliance": 20,
    "region": 30,
    "tenant": 40,
    "app": 50,
    "local_override": 60,
}

EFFECT_PRECEDENCE: dict[str, int] = {
    "deny": 0,
    "require_approval": 1,
    "allow": 2,
    "transform": 3,
}


@dataclass(frozen=True)
class PolicyLayer:
    name: str
    level: PolicyLayerLevel
    policy: dict[str, Any]
    source: str | None = None
    allow_broadening: bool = False
    expires_at: str | None = None
    ticket: str | None = None

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        level: PolicyLayerLevel,
        name: str | None = None,
        allow_broadening: bool = False,
        expires_at: str | None = None,
        ticket: str | None = None,
    ) -> "PolicyLayer":
        file_path = Path(path)
        policy = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
        if not isinstance(policy, dict):
            raise PolicyCompositionError(f"Policy layer must be a YAML mapping: {file_path}")
        return cls(
            name=name or str(policy.get("id") or file_path.stem),
            level=level,
            policy=policy,
            source=str(file_path),
            allow_broadening=allow_broadening,
            expires_at=expires_at,
            ticket=ticket,
        )


@dataclass(frozen=True)
class PolicyCompositionFinding:
    severity: Literal["info", "warning", "error"]
    code: str
    message: str
    layer: str | None = None
    rule: str | None = None
    blocked_by: str | None = None


@dataclass
class PolicyCompositionReport:
    layers: list[str] = field(default_factory=list)
    findings: list[PolicyCompositionFinding] = field(default_factory=list)
    composed_policy: dict[str, Any] = field(default_factory=dict)

    @property
    def has_errors(self) -> bool:
        return any(finding.severity == "error" for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "layers": self.layers,
            "findings": [finding.__dict__ for finding in self.findings],
            "has_errors": self.has_errors,
            "composed_policy": self.composed_policy,
        }


class PolicyCompositionError(ValueError):
    pass


class PolicyComposer:
    """Compose multiple policy layers into one deterministic PolicyAware policy.

    Composition keeps the final policy compatible with the existing PolicyEngine.
    The final engine still evaluates deny first. The composer adds enterprise
    hygiene around distributed policy stacks:

    1. Emergency and higher-precedence layers are ordered before local layers.
    2. Explicit deny rules are never removed by a lower layer.
    3. Local broadening is flagged unless explicitly marked as an exception.
    4. Rule names are namespaced to avoid duplicate-name schema failures.
    """

    def __init__(self, *, strict: bool = True):
        self.strict = strict

    def compose(self, layers: list[PolicyLayer]) -> PolicyCompositionReport:
        if not layers:
            raise PolicyCompositionError("At least one policy layer is required.")
        ordered = sorted(layers, key=lambda layer: LAYER_PRECEDENCE[layer.level])
        report = PolicyCompositionReport(
            layers=[f"{layer.level}:{layer.name}" for layer in ordered],
            composed_policy={
                "id": "composed_policyaware_policy",
                "schema_version": "0.4",
                "default": "deny",
                "rules": [],
            },
        )

        protected_denies: list[tuple[PolicyLayer, dict[str, Any]]] = []
        composed_rules: list[dict[str, Any]] = []
        guards = self._merge_guards(ordered)
        if guards:
            report.composed_policy["guards"] = guards

        for layer in ordered:
            self._validate_layer(layer, report)
            for rule in layer.policy.get("rules", []) or []:
                if not isinstance(rule, dict):
                    continue
                if rule.get("effect") == "allow":
                    blocker = self._matching_protected_deny(rule, protected_denies)
                    if blocker is not None and not layer.allow_broadening:
                        report.findings.append(
                            PolicyCompositionFinding(
                                severity="error" if self.strict else "warning",
                                code="POLICY_COMPOSITION.DENY_OVERRIDE_BLOCKED",
                                message=(
                                    "Lower-precedence allow overlaps a higher-precedence deny. "
                                    "Explicit deny wins; add a signed/time-bound exception if this is intentional."
                                ),
                                layer=layer.name,
                                rule=str(rule.get("name")),
                                blocked_by=f"{blocker[0].level}:{blocker[0].name}:{blocker[1].get('name')}",
                            )
                        )
                        continue
                    if layer.allow_broadening:
                        self._record_exception_metadata(layer, rule, report)
                if rule.get("effect") == "deny":
                    protected_denies.append((layer, rule))
                composed_rules.append(self._namespaced_rule(layer, rule))

        composed_rules.sort(key=self._rule_sort_key)
        report.composed_policy["rules"] = composed_rules
        try:
            PolicyEngine(report.composed_policy)
        except Exception as exc:
            report.findings.append(
                PolicyCompositionFinding(
                    severity="error",
                    code="POLICY_COMPOSITION.INVALID_COMPOSED_POLICY",
                    message=str(exc),
                )
            )
        return report

    def _validate_layer(self, layer: PolicyLayer, report: PolicyCompositionReport) -> None:
        if layer.level not in LAYER_PRECEDENCE:
            raise PolicyCompositionError(f"Unsupported policy layer level: {layer.level}")
        default = layer.policy.get("default", "deny")
        if default != "deny":
            report.findings.append(
                PolicyCompositionFinding(
                    severity="warning",
                    code="POLICY_COMPOSITION.DEFAULT_NOT_DENY",
                    message="Layer default is not deny. Composed policies always use default: deny.",
                    layer=layer.name,
                )
            )
        if layer.allow_broadening and (not layer.expires_at or not layer.ticket):
            report.findings.append(
                PolicyCompositionFinding(
                    severity="error" if self.strict else "warning",
                    code="POLICY_COMPOSITION.EXCEPTION_METADATA_REQUIRED",
                    message=(
                        "Broadening exceptions must include both expires_at and ticket so local overrides "
                        "are auditable and time-bound."
                    ),
                    layer=layer.name,
                )
            )

    def _matching_protected_deny(
        self,
        allow_rule: dict[str, Any],
        protected_denies: list[tuple[PolicyLayer, dict[str, Any]]],
    ) -> tuple[PolicyLayer, dict[str, Any]] | None:
        allow_when = allow_rule.get("when", {}) or {}
        for layer, deny_rule in protected_denies:
            deny_when = deny_rule.get("when", {}) or {}
            if self._conditions_overlap(deny_when, allow_when):
                return layer, deny_rule
        return None

    def _conditions_overlap(self, deny_when: dict[str, Any], allow_when: dict[str, Any]) -> bool:
        if not deny_when:
            return True
        if not allow_when:
            return True
        # Treat a lower allow as a blocked override only when it explicitly
        # covers the higher deny conditions. A broad app allow can coexist with
        # a global deny because the composed PolicyEngine still evaluates deny
        # rules first at runtime.
        if not set(deny_when).issubset(set(allow_when)):
            return False
        for key in deny_when:
            if not self._value_overlap(deny_when[key], allow_when[key]):
                return False
        return True

    def _value_overlap(self, left: Any, right: Any) -> bool:
        left_values = set(left) if isinstance(left, list) else {left}
        right_values = set(right) if isinstance(right, list) else {right}
        return bool(left_values & right_values)

    def _namespaced_rule(self, layer: PolicyLayer, rule: dict[str, Any]) -> dict[str, Any]:
        allowed = {"name", "effect", "when", "action"}
        clean = {key: value for key, value in rule.items() if key in allowed}
        clean["name"] = f"{layer.level}.{layer.name}.{clean.get('name', 'unnamed_rule')}"
        return clean

    def _rule_sort_key(self, rule: dict[str, Any]) -> tuple[int, int]:
        name = str(rule.get("name", ""))
        level = name.split(".", 1)[0]
        return (
            EFFECT_PRECEDENCE.get(str(rule.get("effect")), 99),
            LAYER_PRECEDENCE.get(level, 99),
        )

    def _merge_guards(self, layers: list[PolicyLayer]) -> dict[str, Any]:
        merged: dict[str, list[dict[str, Any]]] = {}
        for layer in layers:
            guards = layer.policy.get("guards") or {}
            if not isinstance(guards, dict):
                continue
            for phase in ("input", "output"):
                entries = guards.get(phase) or []
                if entries:
                    merged.setdefault(phase, []).extend(entries)
        return merged

    def _record_exception_metadata(
        self,
        layer: PolicyLayer,
        rule: dict[str, Any],
        report: PolicyCompositionReport,
    ) -> None:
        report.findings.append(
            PolicyCompositionFinding(
                severity="warning",
                code="POLICY_COMPOSITION.BROADENING_EXCEPTION",
                message=(
                    f"Layer broadens policy with exception ticket={layer.ticket} "
                    f"expires_at={layer.expires_at}."
                ),
                layer=layer.name,
                rule=str(rule.get("name")),
            )
        )


def load_policy_layers(manifest_path: str | Path) -> list[PolicyLayer]:
    manifest_file = Path(manifest_path)
    manifest = yaml.safe_load(manifest_file.read_text(encoding="utf-8")) or {}
    if not isinstance(manifest, dict):
        raise PolicyCompositionError("Composition manifest must be a YAML mapping/object.")
    raw_layers = manifest.get("layers")
    if not isinstance(raw_layers, list) or not raw_layers:
        raise PolicyCompositionError("Composition manifest must include a non-empty layers list.")
    layers: list[PolicyLayer] = []
    for index, item in enumerate(raw_layers):
        if not isinstance(item, dict):
            raise PolicyCompositionError(f"layers[{index}] must be a mapping/object.")
        path = item.get("path")
        level = item.get("level")
        if not path or not level:
            raise PolicyCompositionError(f"layers[{index}] requires path and level.")
        layer_path = Path(path)
        if not layer_path.is_absolute():
            layer_path = manifest_file.parent / layer_path
        layers.append(
            PolicyLayer.from_file(
                layer_path,
                level=level,
                name=item.get("name"),
                allow_broadening=bool(item.get("allow_broadening", False)),
                expires_at=item.get("expires_at"),
                ticket=item.get("ticket"),
            )
        )
    return layers
