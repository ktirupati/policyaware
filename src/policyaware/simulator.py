from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

from policyaware.gateway import Gateway
from policyaware.models import GatewayRequest, GatewayResponse


class VisualPolicySimulator:
    """Generate a static, shareable HTML explanation for one policy decision."""

    def simulate(
        self,
        policy_file: str | Path,
        *,
        prompt: str,
        role: str = "developer",
        tenant: str = "default",
        app: str = "policy-simulator",
        risk: str = "low",
        context: dict[str, Any] | None = None,
    ) -> GatewayResponse:
        gateway = Gateway.from_policy_file(Path(policy_file))
        merged_context = {"region": "us", "risk": risk, "task_type": "simulation"}
        if context:
            merged_context.update(context)
        return gateway.chat(
            GatewayRequest(
                tenant=tenant,
                app=app,
                user={"id": "sim_user", "role": role},
                context=merged_context,
                messages=[{"role": "user", "content": prompt}],
            )
        )

    def write_html(
        self,
        response: GatewayResponse,
        path: str | Path,
        *,
        prompt: str,
        policy_file: str | Path,
    ) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        policy = response.policy
        color = {
            "allow": "#137333",
            "conditional_allow": "#8a5a00",
            "require_approval": "#b06000",
            "deny": "#b42318",
        }.get(policy.decision.value, "#1f2937")
        html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PolicyAware Visual Policy Simulator</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; color: #172033; background: #f7f9fc; }}
    header {{ background: #163b57; color: white; padding: 28px 36px; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }}
    .card {{ background: white; border: 1px solid #d9e2ec; border-radius: 8px; padding: 16px; }}
    .decision {{ color: {color}; font-size: 32px; font-weight: 700; }}
    .label {{ color: #52606d; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }}
    pre {{ white-space: pre-wrap; background: #f0f4f8; border-radius: 6px; padding: 12px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; }}
    th, td {{ border: 1px solid #d9e2ec; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: #163b57; color: white; }}
  </style>
</head>
<body>
  <header>
    <h1>PolicyAware Visual Policy Simulator</h1>
    <p>Policy: {escape(str(policy_file))}</p>
  </header>
  <main>
    <section class="grid">
      <div class="card"><div class="label">Decision</div><div class="decision">{escape(policy.decision.value)}</div></div>
      <div class="card"><div class="label">Risk Tier</div><div class="decision">{escape(policy.risk_tier.value)}</div></div>
      <div class="card"><div class="label">Trace</div><pre>{escape(response.trace_id)}</pre></div>
    </section>
    <section class="card">
      <h2>Input Prompt</h2>
      <pre>{escape(prompt)}</pre>
    </section>
    <section class="card">
      <h2>Decision Explanation</h2>
      <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>Reason</td><td>{escape(policy.reason)}</td></tr>
        <tr><td>Matched rules</td><td>{escape(', '.join(policy.matched_rules) or '-')}</td></tr>
        <tr><td>Violated rules</td><td>{escape(', '.join(policy.violated_rules) or '-')}</td></tr>
        <tr><td>Reason codes</td><td>{escape(', '.join(policy.reason_codes) or '-')}</td></tr>
        <tr><td>Actions</td><td>{escape(', '.join(policy.actions) or '-')}</td></tr>
        <tr><td>Remediation</td><td>{escape('; '.join(policy.remediation) or '-')}</td></tr>
      </table>
    </section>
    <section class="card">
      <h2>Model-Safe Output</h2>
      <pre>{escape(response.content)}</pre>
    </section>
  </main>
</body>
</html>
"""
        output.write_text(html, encoding="utf-8")
        return output
