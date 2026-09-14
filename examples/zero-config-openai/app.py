import policyaware
from openai import OpenAI

gateway = policyaware.Gateway.from_policy_file("policy.yaml")
client = OpenAI()
user_context = {"user_role": "billing_admin", "session_id": "99x-delta", "risk": "low"}
safe_prompt, token_meta = gateway.inspect_and_mutate(
    prompt="Email jane@example.com about claim ACME-42.",
    context=user_context,
    app="zero-config",
)
print(token_meta["decision"], token_meta["actions"])
response = client.responses.create(model="gpt-4.1-mini", input=safe_prompt)
print(response.output_text)
