from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib.util import find_spec
from typing import Any, Pattern


@dataclass(frozen=True)
class PerformanceBackendStatus:
    backend: str
    native_available: bool
    reason: str


class FastCoreRuntime:
    """Small facade for performance-sensitive primitives.

    The base package remains pure Python and lightweight. If a future optional
    native accelerator is installed, this class can delegate hot-path JSON,
    regex, and protocol parsing work without changing the public API.
    """

    def __init__(self, *, prefer_native: bool = True) -> None:
        self.prefer_native = prefer_native
        self._native = self._load_native() if prefer_native else None

    @property
    def status(self) -> PerformanceBackendStatus:
        if self._native is not None:
            return PerformanceBackendStatus(
                backend="native",
                native_available=True,
                reason="Native accelerator module is available.",
            )
        if self.prefer_native and find_spec("policyaware_fast") is None:
            return PerformanceBackendStatus(
                backend="python",
                native_available=False,
                reason="Optional policyaware_fast accelerator is not installed.",
            )
        return PerformanceBackendStatus(
            backend="python",
            native_available=False,
            reason="Pure-Python runtime selected.",
        )

    def loads_json(self, payload: str) -> Any:
        if self._native is not None and hasattr(self._native, "loads_json"):
            return self._native.loads_json(payload)
        return json.loads(payload)

    def dumps_json(self, payload: Any) -> str:
        if self._native is not None and hasattr(self._native, "dumps_json"):
            return self._native.dumps_json(payload)
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)

    def compile_regex(self, pattern: str, flags: int = 0) -> Pattern[str]:
        return re.compile(pattern, flags)

    def find_regex(self, pattern: str | Pattern[str], text: str) -> list[str]:
        compiled = pattern if hasattr(pattern, "findall") else self.compile_regex(str(pattern))
        return [str(match) for match in compiled.findall(text)]

    @staticmethod
    def _load_native() -> Any | None:
        if find_spec("policyaware_fast") is None:
            return None
        try:
            import policyaware_fast  # type: ignore[import-not-found]
        except Exception:
            return None
        return policyaware_fast


def performance_status(*, prefer_native: bool = True) -> PerformanceBackendStatus:
    return FastCoreRuntime(prefer_native=prefer_native).status
