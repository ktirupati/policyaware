from __future__ import annotations

from policyaware.models import GatewayRequest


def safe_rewrite_state(request: GatewayRequest) -> dict[str, object]:
    """Return an auditable state patch that nudges an agent toward safer execution."""

    original_messages = [dict(message) for message in request.messages]
    safety_message = {
        "role": "system",
        "content": (
            "PolicyAware safety rewrite: continue only with read-only, least-privilege steps. "
            "Do not delete, deploy, transfer funds, change permissions, or send data externally "
            "unless a human approval workflow explicitly authorizes that action. Preserve audit "
            "metadata and cite the policy decision in the next tool call."
        ),
    }
    rewritten_messages = [safety_message, *original_messages]
    return {
        "type": "rewrite_context",
        "reason": "Risky trajectory matched a safe_rewrite transform rule.",
        "messages": rewritten_messages,
        "instructions": [
            "Continue with read-only investigation first.",
            "Require approval before side-effecting tool calls.",
            "Keep trace, tenant, role, tool/action, and reason-code metadata.",
        ],
    }
