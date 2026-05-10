import pytest

from policyaware.policy import PolicyEngine
from policyaware.policy_schema import PolicySchemaValidator, PolicyValidationError


def test_valid_policy_passes_schema_validation() -> None:
    PolicySchemaValidator().validate(
        {
            "id": "valid",
            "default": "deny",
            "rules": [
                {
                    "name": "allow_support",
                    "effect": "allow",
                    "when": {"user.role_in": ["support_agent"]},
                }
            ],
        }
    )


def test_policy_engine_rejects_invalid_policy() -> None:
    with pytest.raises(PolicyValidationError):
        PolicyEngine({"default": "maybe", "rules": []})


def test_missing_rule_name_is_reported() -> None:
    with pytest.raises(PolicyValidationError) as exc:
        PolicySchemaValidator().validate({"rules": [{"effect": "allow", "when": {}}]})

    assert "rules[0].name is required" in str(exc.value)


def test_invalid_effect_is_reported() -> None:
    with pytest.raises(PolicyValidationError) as exc:
        PolicySchemaValidator().validate(
            {"rules": [{"name": "bad", "effect": "permit", "when": {}}]}
        )

    assert "rules[0].effect must be one of" in str(exc.value)


def test_transform_requires_supported_action() -> None:
    with pytest.raises(PolicyValidationError) as exc:
        PolicySchemaValidator().validate(
            {"rules": [{"name": "bad", "effect": "transform", "action": "encrypt", "when": {}}]}
        )

    assert "rules[0].action must be one of" in str(exc.value)


def test_non_transform_rule_cannot_have_action() -> None:
    with pytest.raises(PolicyValidationError) as exc:
        PolicySchemaValidator().validate(
            {"rules": [{"name": "bad", "effect": "allow", "action": "redact", "when": {}}]}
        )

    assert "rules[0].action is only valid" in str(exc.value)


def test_in_operator_requires_list() -> None:
    with pytest.raises(PolicyValidationError) as exc:
        PolicySchemaValidator().validate(
            {"rules": [{"name": "bad", "effect": "allow", "when": {"user.role_in": "admin"}}]}
        )

    assert "must have a list value" in str(exc.value)


def test_condition_root_must_be_supported() -> None:
    with pytest.raises(PolicyValidationError) as exc:
        PolicySchemaValidator().validate(
            {"rules": [{"name": "bad", "effect": "allow", "when": {"identity.role": "admin"}}]}
        )

    assert "unsupported root 'identity'" in str(exc.value)


def test_duplicate_rule_names_are_reported() -> None:
    with pytest.raises(PolicyValidationError) as exc:
        PolicySchemaValidator().validate(
            {
                "rules": [
                    {"name": "same", "effect": "allow", "when": {}},
                    {"name": "same", "effect": "deny", "when": {}},
                ]
            }
        )

    assert "duplicated" in str(exc.value)

