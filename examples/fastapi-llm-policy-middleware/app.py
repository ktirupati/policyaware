from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from policyaware import Gateway, GatewayRequest


gateway = Gateway.from_policy_file("policy.yaml")
app = FastAPI(title="PolicyAware FastAPI LLM Policy Middleware")


class ChatRequest(BaseModel):
    prompt: str
    role: str = "support_agent"
    region: str = "us"


@app.post("/chat")
def chat(body: ChatRequest) -> dict[str, object]:
    response = gateway.chat(
        GatewayRequest(
            tenant="acme",
            app="fastapi-llm-policy-middleware",
            user={"id": "api_user", "role": body.role},
            context={"region": body.region, "task_type": "support_chat", "risk": "low"},
            messages=[{"role": "user", "content": body.prompt}],
        )
    )
    return {
        "decision": response.policy.decision.value,
        "reason_codes": response.policy.reason_codes,
        "actions": response.policy.actions,
        "content": response.content,
        "trace_id": response.trace_id,
    }

