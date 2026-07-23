from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from policyaware.models import GatewayRequest


class OptionalGuardrailsDependencyError(ImportError):
    """Raised when an optional guardrails integration dependency is not installed."""


@dataclass(frozen=True)
class GuardrailResult:
    """Normalized result returned by optional guardrail adapters."""

    name: str
    allowed: bool = True
    transformed_text: str | None = None
    reason: str = "Allowed by guardrail."
    score: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


class GuardrailAdapter(Protocol):
    """Protocol for input/output guard adapters."""

    name: str

    def inspect_input(self, request: GatewayRequest) -> GuardrailResult:
        ...

    def inspect_output(self, request: GatewayRequest, output_text: str) -> GuardrailResult:
        ...


class BaseGuardrailAdapter:
    name = "base"

    def inspect_input(self, request: GatewayRequest) -> GuardrailResult:
        return GuardrailResult(name=self.name)

    def inspect_output(self, request: GatewayRequest, output_text: str) -> GuardrailResult:
        return GuardrailResult(name=self.name)


class NeMoGuardrailsAdapter(BaseGuardrailAdapter):
    """Optional adapter for NVIDIA NeMo Guardrails.

    The adapter is intentionally thin: PolicyAware remains the governance control
    plane, while NeMo can be plugged in for conversational rails. Pass an already
    configured `rails` object for advanced usage, or use `config_path` to lazily
    construct `LLMRails` from a NeMo rails config directory.
    """

    name = "nemo"

    def __init__(
        self,
        *,
        rails: Any | None = None,
        config_path: str | Path | None = None,
        block_markers: tuple[str, ...] = ("i'm sorry", "cannot comply", "blocked", "not allowed"),
    ) -> None:
        self.rails = rails or self._load_rails(config_path)
        self.config_path = str(config_path) if config_path else None
        self.block_markers = tuple(marker.lower() for marker in block_markers)

    def inspect_input(self, request: GatewayRequest) -> GuardrailResult:
        if self.rails is None:
            return GuardrailResult(
                name=self.name,
                metadata={"configured": False, "config_path": self.config_path},
            )
        output = self._generate(request)
        if output is None:
            return GuardrailResult(
                name=self.name,
                metadata={"configured": True, "mode": "passive"},
            )
        allowed = not any(marker in output.lower() for marker in self.block_markers)
        return GuardrailResult(
            name=self.name,
            allowed=allowed,
            reason="Allowed by NeMo Guardrails." if allowed else "Blocked by NeMo Guardrails.",
            score=1.0 if allowed else 0.0,
            metadata={"configured": True, "preview": output[:240]},
        )

    def _generate(self, request: GatewayRequest) -> str | None:
        generate = getattr(self.rails, "generate", None)
        if generate is None:
            return None
        messages = [
            {"role": message.get("role", "user"), "content": message.get("content", "")}
            for message in request.messages
        ]
        try:
            result = generate(messages=messages)
        except TypeError:
            result = generate(prompt=request.prompt_text)
        except Exception as exc:
            return f"NeMo Guardrails execution error: {exc}"
        if isinstance(result, dict):
            return str(result.get("content") or result.get("text") or result)
        return str(result)

    def _load_rails(self, config_path: str | Path | None) -> Any | None:
        if config_path is None:
            return None
        try:
            from nemoguardrails import LLMRails, RailsConfig
        except ImportError as exc:
            raise OptionalGuardrailsDependencyError(
                'NeMo Guardrails is optional. Install it with `pip install "policyaware[nemo]"`.'
            ) from exc
        config = RailsConfig.from_path(str(config_path))
        return LLMRails(config)


class GuardrailsAIAdapter(BaseGuardrailAdapter):
    """Optional adapter for Guardrails AI validation.

    Accepts a Guardrails AI `Guard` instance or any object exposing `validate`,
    `parse`, or `__call__`. This keeps PolicyAware independent from Guardrails
    AI's application-specific validator choices while preserving a single audit
    and policy flow.
    """

    name = "guardrails_ai"

    def __init__(
        self,
        *,
        guard: Any | None = None,
        rail_spec: str | Path | None = None,
        validate_input: bool = True,
        validate_output: bool = True,
    ) -> None:
        self.guard = guard or self._load_guard(rail_spec)
        self.rail_spec = str(rail_spec) if rail_spec else None
        self.validate_input = validate_input
        self.validate_output = validate_output

    def inspect_input(self, request: GatewayRequest) -> GuardrailResult:
        if not self.validate_input:
            return GuardrailResult(name=self.name, metadata={"skipped": "input"})
        return self._validate_text(request.prompt_text, phase="input")

    def inspect_output(self, request: GatewayRequest, output_text: str) -> GuardrailResult:
        if not self.validate_output:
            return GuardrailResult(name=self.name, metadata={"skipped": "output"})
        return self._validate_text(output_text, phase="output")

    def _validate_text(self, text: str, *, phase: str) -> GuardrailResult:
        if self.guard is None:
            return GuardrailResult(
                name=self.name,
                metadata={"configured": False, "phase": phase, "rail_spec": self.rail_spec},
            )
        try:
            result = self._call_guard(text)
        except Exception as exc:
            return GuardrailResult(
                name=self.name,
                allowed=False,
                reason=f"Guardrails AI validation failed: {exc}",
                score=0.0,
                metadata={"phase": phase, "error": str(exc)},
            )
        allowed = _guardrails_validation_passed(result)
        transformed = _guardrails_validated_output(result)
        return GuardrailResult(
            name=self.name,
            allowed=allowed,
            transformed_text=transformed if transformed != text else None,
            reason="Allowed by Guardrails AI." if allowed else "Blocked by Guardrails AI.",
            score=1.0 if allowed else 0.0,
            metadata={"phase": phase, "result_type": type(result).__name__},
        )

    def _call_guard(self, text: str) -> Any:
        if hasattr(self.guard, "validate"):
            return self.guard.validate(text)
        if hasattr(self.guard, "parse"):
            return self.guard.parse(text)
        return self.guard(text)

    def _load_guard(self, rail_spec: str | Path | None) -> Any | None:
        if rail_spec is None:
            return None
        try:
            import guardrails as gd
        except ImportError as exc:
            raise OptionalGuardrailsDependencyError(
                'Guardrails AI is optional. Install it with `pip install "policyaware[guardrails-ai]"`.'
            ) from exc
        spec = Path(rail_spec)
        if spec.exists() and hasattr(gd, "Guard"):
            guard_cls = gd.Guard
            if hasattr(guard_cls, "from_rail"):
                return guard_cls.from_rail(str(spec))
            if hasattr(guard_cls, "from_rail_string"):
                return guard_cls.from_rail_string(spec.read_text(encoding="utf-8"))
        if hasattr(gd, "Guard") and hasattr(gd.Guard, "from_rail_string"):
            return gd.Guard.from_rail_string(str(rail_spec))
        return None


def _guardrails_validation_passed(result: Any) -> bool:
    if isinstance(result, bool):
        return result
    for attr in ("validation_passed", "validated", "passed", "success"):
        value = getattr(result, attr, None)
        if isinstance(value, bool):
            return value
    if isinstance(result, dict):
        for key in ("validation_passed", "validated", "passed", "success"):
            if isinstance(result.get(key), bool):
                return bool(result[key])
    return True


def _guardrails_validated_output(result: Any) -> str | None:
    for attr in ("validated_output", "output", "value"):
        value = getattr(result, attr, None)
        if value is not None:
            return str(value)
    if isinstance(result, dict):
        for key in ("validated_output", "output", "value"):
            if result.get(key) is not None:
                return str(result[key])
    if isinstance(result, str):
        return result
    return None
