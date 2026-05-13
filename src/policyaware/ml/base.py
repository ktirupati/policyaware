from __future__ import annotations

from typing import Protocol

from policyaware.models import GatewayRequest, MLAssessment, MLSignal


class OptionalMLDependencyError(ImportError):
    def __init__(self, integration: str, install: str):
        super().__init__(
            f"{integration} requires optional dependencies. Install them with: {install}"
        )


class MLClassifier(Protocol):
    def classify(self, text: str, request: GatewayRequest | None = None) -> MLAssessment:
        ...


class NoopMLClassifier:
    def classify(self, text: str, request: GatewayRequest | None = None) -> MLAssessment:
        return MLAssessment()


class StaticMLClassifier:
    def __init__(self, signals: dict[str, MLSignal]):
        self.signals = signals

    def classify(self, text: str, request: GatewayRequest | None = None) -> MLAssessment:
        return MLAssessment(signals=self.signals)


class CompositeMLClassifier:
    def __init__(self, classifiers: list[MLClassifier] | None = None):
        self.classifiers = classifiers or []

    def classify(self, text: str, request: GatewayRequest | None = None) -> MLAssessment:
        signals: dict[str, MLSignal] = {}
        metadata = {"classifiers": []}
        for classifier in self.classifiers:
            assessment = classifier.classify(text, request)
            signals.update(assessment.signals)
            metadata["classifiers"].append(classifier.__class__.__name__)
        return MLAssessment(signals=signals, metadata=metadata)
