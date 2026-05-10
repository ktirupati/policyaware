from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class PolicyValidationError(ValueError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("\n".join(errors))


@dataclass(frozen=True)
class PolicySchemaValidator:
    allowed_top_level: frozenset[str] = frozenset({"id", "schema_version", "default", "rules"})
    allowed_rule_fields: frozenset[str] = frozenset({"name", "effect", "when", "action"})
    allowed_effects: frozenset[str] = frozenset({"allow", "deny", "transform", "require_approval"})
    allowed_actions: frozenset[str] = frozenset(
        {"redact", "mask", "log", "route_to_safe_model", "require_approval"}
    )
    allowed_roots: frozenset[str] = frozenset({"tenant", "app", "user", "request", "data", "risk"})
    operator_suffixes: tuple[str, ...] = ("_not_in", "_in", "_lte", "_gte")

    def validate(self, policy: dict[str, Any]) -> None:
        errors: list[str] = []
        if not isinstance(policy, dict):
            raise PolicyValidationError(["Policy must be a mapping/object."])

        self._validate_top_level(policy, errors)
        self._validate_default(policy, errors)
        self._validate_rules(policy, errors)

        if errors:
            raise PolicyValidationError(errors)

    def _validate_top_level(self, policy: dict[str, Any], errors: list[str]) -> None:
        for key in policy:
            if key not in self.allowed_top_level:
                errors.append(
                    f"Unknown top-level field '{key}'. Allowed fields: {sorted(self.allowed_top_level)}."
                )
        if "id" in policy and not isinstance(policy["id"], str):
            errors.append("Field 'id' must be a string.")

    def _validate_default(self, policy: dict[str, Any], errors: list[str]) -> None:
        default = policy.get("default", "deny")
        if default not in {"allow", "deny"}:
            errors.append("Field 'default' must be either 'allow' or 'deny'.")

    def _validate_rules(self, policy: dict[str, Any], errors: list[str]) -> None:
        rules = policy.get("rules", [])
        if not isinstance(rules, list):
            errors.append("Field 'rules' must be a list.")
            return

        seen_names: set[str] = set()
        for index, rule in enumerate(rules):
            path = f"rules[{index}]"
            if not isinstance(rule, dict):
                errors.append(f"{path} must be a mapping/object.")
                continue
            self._validate_rule_fields(rule, path, errors)
            self._validate_rule_name(rule, path, seen_names, errors)
            self._validate_rule_effect(rule, path, errors)
            self._validate_rule_action(rule, path, errors)
            self._validate_when(rule.get("when", {}), path, errors)

    def _validate_rule_fields(self, rule: dict[str, Any], path: str, errors: list[str]) -> None:
        for key in rule:
            if key not in self.allowed_rule_fields:
                errors.append(
                    f"{path} has unknown field '{key}'. Allowed fields: {sorted(self.allowed_rule_fields)}."
                )

    def _validate_rule_name(
        self, rule: dict[str, Any], path: str, seen_names: set[str], errors: list[str]
    ) -> None:
        name = rule.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{path}.name is required and must be a non-empty string.")
            return
        if name in seen_names:
            errors.append(f"{path}.name '{name}' is duplicated.")
        seen_names.add(name)

    def _validate_rule_effect(self, rule: dict[str, Any], path: str, errors: list[str]) -> None:
        effect = rule.get("effect")
        if effect not in self.allowed_effects:
            errors.append(f"{path}.effect must be one of {sorted(self.allowed_effects)}.")

    def _validate_rule_action(self, rule: dict[str, Any], path: str, errors: list[str]) -> None:
        effect = rule.get("effect")
        action = rule.get("action")
        if effect == "transform":
            if action not in self.allowed_actions:
                errors.append(f"{path}.action must be one of {sorted(self.allowed_actions)}.")
        elif action is not None:
            errors.append(f"{path}.action is only valid when effect is 'transform'.")

    def _validate_when(self, when: Any, path: str, errors: list[str]) -> None:
        if when is None:
            return
        if not isinstance(when, dict):
            errors.append(f"{path}.when must be a mapping/object.")
            return
        for condition_key, expected in when.items():
            if not isinstance(condition_key, str) or "." not in self._base_key(condition_key):
                errors.append(
                    f"{path}.when key '{condition_key}' must be a dotted path like 'user.role'."
                )
                continue
            base_key, operator = self._split_operator(condition_key)
            root = base_key.split(".", 1)[0]
            if root not in self.allowed_roots:
                errors.append(
                    f"{path}.when key '{condition_key}' has unsupported root '{root}'. "
                    f"Allowed roots: {sorted(self.allowed_roots)}."
                )
            self._validate_condition_value(condition_key, operator, expected, path, errors)

    def _split_operator(self, key: str) -> tuple[str, str]:
        for suffix in self.operator_suffixes:
            if key.endswith(suffix):
                return key[: -len(suffix)], suffix[1:]
        return key, "eq"

    def _base_key(self, key: str) -> str:
        return self._split_operator(key)[0]

    def _validate_condition_value(
        self, key: str, operator: str, expected: Any, path: str, errors: list[str]
    ) -> None:
        if operator in {"in", "not_in"} and not isinstance(expected, list):
            errors.append(f"{path}.when '{key}' must have a list value for '{operator}'.")
        if operator in {"lte", "gte"} and not isinstance(expected, (int, float)):
            errors.append(f"{path}.when '{key}' must have a numeric value for '{operator}'.")
