"""Framework integration shims."""

from policyaware.integrations.callbacks import BasePolicyAwareCallbackHandler, PolicyAwareCallbackResult
from policyaware.integrations.fastapi import PolicyAwareMiddleware, policyaware_json_response
from policyaware.integrations.langgraph import PolicyAwareNodeGuard, PolicyAwareNodeResult
from policyaware.integrations.recommender import (
    IntegrationRecommendation,
    IntegrationRecommendationReport,
    IntegrationRecommender,
)

__all__ = [
    "BasePolicyAwareCallbackHandler",
    "IntegrationRecommendation",
    "IntegrationRecommendationReport",
    "IntegrationRecommender",
    "PolicyAwareCallbackResult",
    "PolicyAwareMiddleware",
    "PolicyAwareNodeGuard",
    "PolicyAwareNodeResult",
    "policyaware_json_response",
]
