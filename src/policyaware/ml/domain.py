from __future__ import annotations

from typing import Any

from policyaware.ml.base import OptionalMLDependencyError
from policyaware.models import GatewayRequest, MLAssessment, MLSignal


class TransformersDomainRiskClassifier:
    def __init__(
        self,
        *,
        model_name: str,
        signal_name: str = "domain",
        provider: str = "huggingface",
        threshold: float = 0.5,
        pipeline_kwargs: dict[str, Any] | None = None,
    ):
        try:
            from transformers import pipeline
        except ImportError as exc:
            raise OptionalMLDependencyError(
                "Transformers domain/risk classifier",
                'pip install "policyaware[ml]"',
            ) from exc

        self.model_name = model_name
        self.signal_name = signal_name
        self.provider = provider
        self.threshold = threshold
        self._pipeline = pipeline(
            "text-classification",
            model=model_name,
            **(pipeline_kwargs or {}),
        )

    def classify(self, text: str, request: GatewayRequest | None = None) -> MLAssessment:
        result = self._pipeline(text, truncation=True)
        if isinstance(result, list):
            result = result[0]
        label = str(result.get("label", "")).lower()
        score = float(result.get("score", 0.0))
        signal = MLSignal(
            name=self.signal_name,
            label=label,
            score=score,
            detected=score >= self.threshold,
            provider=self.provider,
            model=self.model_name,
            metadata={"threshold": self.threshold},
        )
        return MLAssessment(signals={self.signal_name: signal})
