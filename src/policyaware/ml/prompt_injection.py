from __future__ import annotations

from typing import Any

from policyaware.ml.base import OptionalMLDependencyError
from policyaware.models import GatewayRequest, MLAssessment, MLSignal


class ProtectAIPromptInjectionClassifier:
    def __init__(
        self,
        *,
        model_name: str = "protectai/deberta-v3-small-prompt-injection-v2",
        threshold: float = 0.7,
        use_onnx: bool = False,
        pipeline_kwargs: dict[str, Any] | None = None,
    ):
        self.model_name = model_name
        self.threshold = threshold
        self.use_onnx = use_onnx
        self.pipeline_kwargs = pipeline_kwargs or {}
        self._pipeline = self._load_pipeline()

    def classify(self, text: str, request: GatewayRequest | None = None) -> MLAssessment:
        result = self._pipeline(text, truncation=True, max_length=512)
        if isinstance(result, list):
            result = result[0]
        label = str(result.get("label", "")).lower()
        score = float(result.get("score", 0.0))
        detected = label in {"1", "label_1", "injection", "injection-detected"} and score >= self.threshold
        signal = MLSignal(
            name="prompt_injection",
            label=label,
            score=score,
            detected=detected,
            provider="protectai",
            model=self.model_name,
            metadata={"threshold": self.threshold, "onnx": self.use_onnx},
        )
        return MLAssessment(signals={"prompt_injection": signal})

    def _load_pipeline(self):
        try:
            from transformers import AutoTokenizer, pipeline
        except ImportError as exc:
            raise OptionalMLDependencyError(
                "ProtectAI prompt-injection classifier",
                'pip install "policyaware[ml]"',
            ) from exc

        if self.use_onnx:
            try:
                from optimum.onnxruntime import ORTModelForSequenceClassification
            except ImportError as exc:
                raise OptionalMLDependencyError(
                    "ProtectAI ONNX prompt-injection classifier",
                    'pip install "policyaware[onnx]"',
                ) from exc

            tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                subfolder="onnx",
                use_fast=False,
            )
            tokenizer.model_input_names = ["input_ids", "attention_mask"]
            model = ORTModelForSequenceClassification.from_pretrained(
                self.model_name,
                export=False,
                subfolder="onnx",
            )
            return pipeline(
                task="text-classification",
                model=model,
                tokenizer=tokenizer,
                **self.pipeline_kwargs,
            )

        return pipeline(
            "text-classification",
            model=self.model_name,
            **self.pipeline_kwargs,
        )
