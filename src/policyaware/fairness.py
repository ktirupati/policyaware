from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field


class FairnessDecisionEvent(BaseModel):
    subject_id: str
    outcome: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class FairnessGroupMetric(BaseModel):
    group: str
    total: int
    positive: int
    positive_rate: float


class FairnessReport(BaseModel):
    passed: bool
    protected_attribute: str
    positive_outcomes: list[str]
    threshold: float
    disparity: float
    metrics: list[FairnessGroupMetric] = Field(default_factory=list)
    reason: str
    reason_codes: list[str] = Field(default_factory=list)


@dataclass
class FairnessMonitor:
    """Lightweight real-time distribution monitor for decisioning agents."""

    protected_attribute: str
    positive_outcomes: list[str]
    threshold: float = 0.2
    min_group_size: int = 5
    _events: list[FairnessDecisionEvent] = field(default_factory=list)

    def record(
        self,
        *,
        subject_id: str,
        outcome: str,
        attributes: dict[str, Any],
    ) -> FairnessReport:
        self._events.append(
            FairnessDecisionEvent(subject_id=subject_id, outcome=outcome, attributes=attributes)
        )
        return self.evaluate()

    def evaluate(self) -> FairnessReport:
        buckets: dict[str, list[FairnessDecisionEvent]] = defaultdict(list)
        for event in self._events:
            value = str(event.attributes.get(self.protected_attribute, "unknown"))
            buckets[value].append(event)

        metrics: list[FairnessGroupMetric] = []
        for group, events in buckets.items():
            if len(events) < self.min_group_size:
                continue
            positive = sum(1 for event in events if event.outcome in self.positive_outcomes)
            metrics.append(
                FairnessGroupMetric(
                    group=group,
                    total=len(events),
                    positive=positive,
                    positive_rate=positive / len(events),
                )
            )

        if len(metrics) < 2:
            return FairnessReport(
                passed=True,
                protected_attribute=self.protected_attribute,
                positive_outcomes=self.positive_outcomes,
                threshold=self.threshold,
                disparity=0.0,
                metrics=metrics,
                reason="Not enough group data to compute disparity.",
            )

        rates = [metric.positive_rate for metric in metrics]
        disparity = max(rates) - min(rates)
        passed = disparity <= self.threshold
        return FairnessReport(
            passed=passed,
            protected_attribute=self.protected_attribute,
            positive_outcomes=self.positive_outcomes,
            threshold=self.threshold,
            disparity=round(disparity, 6),
            metrics=metrics,
            reason="Fairness distribution is within threshold."
            if passed
            else "Outcome distribution disparity exceeded the configured fairness threshold.",
            reason_codes=[] if passed else ["FAIRNESS.DISPARITY_THRESHOLD_EXCEEDED"],
        )
