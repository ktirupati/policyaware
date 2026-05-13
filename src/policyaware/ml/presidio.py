from __future__ import annotations

from policyaware.ml.base import OptionalMLDependencyError
from policyaware.models import GatewayRequest, MLAssessment, MLSignal


class PresidioPIIClassifier:
    def __init__(
        self,
        *,
        language: str = "en",
        score_threshold: float = 0.5,
        entities: list[str] | None = None,
    ):
        try:
            from presidio_analyzer import AnalyzerEngine
        except ImportError as exc:
            raise OptionalMLDependencyError("Presidio PII classifier", 'pip install "policyaware[presidio]"') from exc

        self.language = language
        self.score_threshold = score_threshold
        self.entities = entities
        self.analyzer = AnalyzerEngine()

    def classify(self, text: str, request: GatewayRequest | None = None) -> MLAssessment:
        results = self.analyzer.analyze(
            text=text,
            language=self.language,
            entities=self.entities,
            score_threshold=self.score_threshold,
        )
        entities = [
            {
                "entity_type": result.entity_type,
                "score": result.score,
                "start": result.start,
                "end": result.end,
            }
            for result in results
        ]
        top_score = max((entity["score"] for entity in entities), default=0.0)
        signal = MLSignal(
            name="pii",
            label="pii_detected" if entities else "none",
            score=top_score,
            detected=bool(entities),
            provider="presidio",
            model="presidio-analyzer",
            metadata={"entities": entities},
        )
        return MLAssessment(signals={"pii": signal})
