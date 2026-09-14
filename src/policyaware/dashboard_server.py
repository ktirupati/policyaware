from __future__ import annotations

from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from policyaware.simulator import VisualPolicySimulator


DEFAULT_SAMPLE_TRAJECTORY = """User asks to summarize a claim.
Agent reads customer profile.
Agent attempts to email jane@example.com with a phone number.
Agent asks to call payments.refund for a high-risk refund."""


def create_dashboard_app(policy_file: str | Path):
    """Create a FastAPI app when FastAPI is installed.

    This function is intentionally optional. The CLI can run without FastAPI by
    using the built-in stdlib dashboard server.
    """

    try:
        from fastapi import FastAPI, Form
        from fastapi.responses import HTMLResponse
    except ImportError as exc:  # pragma: no cover - exercised by CLI fallback
        raise RuntimeError('Install dashboard extras: pip install "policyaware[dashboard]"') from exc

    app = FastAPI(title="PolicyAware Local Policy Simulator")

    @app.get("/", response_class=HTMLResponse)
    async def home() -> str:
        return render_dashboard_html(policy_file=policy_file)

    @app.post("/simulate", response_class=HTMLResponse)
    async def simulate(
        prompt: str = Form(...),
        role: str = Form("developer"),
        tenant: str = Form("default"),
        risk: str = Form("low"),
    ) -> str:
        result = simulate_payload(policy_file, prompt=prompt, role=role, tenant=tenant, risk=risk)
        return render_dashboard_html(policy_file=policy_file, prompt=prompt, result=result)

    return app


def serve_dashboard(
    policy_file: str | Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = False,
    prefer_fastapi: bool = True,
) -> None:
    if prefer_fastapi:
        try:
            import uvicorn

            app = create_dashboard_app(policy_file)
            if open_browser:
                _open_browser(host, port)
            uvicorn.run(app, host=host, port=port, log_level="info")
            return
        except ImportError:
            pass
        except RuntimeError:
            pass

    server = ThreadingHTTPServer((host, port), _handler_for_policy(policy_file))
    if open_browser:
        _open_browser(host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def simulate_payload(
    policy_file: str | Path,
    *,
    prompt: str,
    role: str,
    tenant: str,
    risk: str,
) -> dict[str, Any]:
    simulator = VisualPolicySimulator()
    response = simulator.simulate(
        policy_file,
        prompt=prompt,
        role=role,
        tenant=tenant,
        risk=risk,
        app="policyaware-dashboard",
        context={"trajectory": prompt},
    )
    policy = response.policy
    return {
        "decision": policy.decision.value,
        "risk_tier": policy.risk_tier.value,
        "reason": policy.reason,
        "matched_rules": policy.matched_rules,
        "violated_rules": policy.violated_rules,
        "reason_codes": policy.reason_codes,
        "actions": policy.actions,
        "remediation": policy.remediation,
        "trace_id": response.trace_id,
        "content": response.content,
    }


def render_dashboard_html(
    *,
    policy_file: str | Path,
    prompt: str = DEFAULT_SAMPLE_TRAJECTORY,
    result: dict[str, Any] | None = None,
) -> str:
    result_html = _render_result(result) if result else _empty_result()
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PolicyAware Dashboard</title>
  <style>
    :root {{ --blue:#173b57; --line:#d9e2ec; --bg:#f6f8fb; --text:#172033; }}
    body {{ margin:0; font-family: Arial, sans-serif; color:var(--text); background:var(--bg); }}
    header {{ background:var(--blue); color:white; padding:24px 36px; }}
    main {{ max-width:1180px; margin:0 auto; padding:24px; display:grid; grid-template-columns: 1fr 1fr; gap:18px; }}
    section {{ background:white; border:1px solid var(--line); border-radius:8px; padding:18px; }}
    label {{ display:block; font-weight:700; margin:12px 0 6px; }}
    textarea, input, select {{ width:100%; box-sizing:border-box; border:1px solid #bcccdc; border-radius:6px; padding:10px; font:inherit; }}
    textarea {{ min-height:270px; }}
    button {{ margin-top:14px; background:#1769aa; color:white; border:0; border-radius:6px; padding:11px 16px; font-weight:700; cursor:pointer; }}
    .row {{ display:grid; grid-template-columns: 1fr 1fr 1fr; gap:10px; }}
    .pill {{ display:inline-block; border-radius:999px; padding:5px 10px; background:#e7f0fa; margin:3px; }}
    .decision {{ font-size:30px; font-weight:800; }}
    .deny {{ color:#b42318; }} .allow {{ color:#137333; }} .approval {{ color:#b06000; }}
    table {{ width:100%; border-collapse:collapse; }}
    th, td {{ border:1px solid var(--line); padding:9px; text-align:left; vertical-align:top; }}
    th {{ background:#edf2f7; }}
    pre {{ white-space:pre-wrap; background:#f0f4f8; padding:12px; border-radius:6px; }}
  </style>
</head>
<body>
  <header>
    <h1>PolicyAware Local Policy Simulator</h1>
    <p>Policy: {escape(str(policy_file))}</p>
  </header>
  <main>
    <section>
      <h2>Simulate A Prompt Or Agent Trajectory</h2>
      <form method="post" action="/simulate">
        <label for="prompt">Prompt / multi-step trajectory</label>
        <textarea id="prompt" name="prompt">{escape(prompt)}</textarea>
        <div class="row">
          <div><label for="role">Role</label><input id="role" name="role" value="developer"></div>
          <div><label for="tenant">Tenant</label><input id="tenant" name="tenant" value="default"></div>
          <div><label for="risk">Risk</label><select id="risk" name="risk"><option>low</option><option>medium</option><option>high</option><option>critical</option></select></div>
        </div>
        <button type="submit">Run Simulation</button>
      </form>
    </section>
    <section>
      <h2>Policy Playback</h2>
      {result_html}
    </section>
  </main>
</body>
</html>"""


def _handler_for_policy(policy_file: str | Path):
    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._write_html(render_dashboard_html(policy_file=policy_file))

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            form = parse_qs(self.rfile.read(length).decode("utf-8"))
            prompt = form.get("prompt", [DEFAULT_SAMPLE_TRAJECTORY])[0]
            role = form.get("role", ["developer"])[0]
            tenant = form.get("tenant", ["default"])[0]
            risk = form.get("risk", ["low"])[0]
            result = simulate_payload(
                policy_file,
                prompt=prompt,
                role=role,
                tenant=tenant,
                risk=risk,
            )
            self._write_html(render_dashboard_html(policy_file=policy_file, prompt=prompt, result=result))

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _write_html(self, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return DashboardHandler


def _render_result(result: dict[str, Any]) -> str:
    decision = str(result.get("decision", "unknown"))
    decision_class = "allow" if decision == "allow" else "approval" if "approval" in decision else "deny"
    return f"""
    <div class="decision {decision_class}">{escape(decision)}</div>
    <p><strong>Risk:</strong> {escape(str(result.get("risk_tier", "-")))} | <strong>Trace:</strong> {escape(str(result.get("trace_id", "-")))}</p>
    <table>
      <tr><th>Step</th><th>What PolicyAware Found</th></tr>
      <tr><td>1. Request context</td><td>Role, tenant, risk, and task metadata were evaluated.</td></tr>
      <tr><td>2. Matched rules</td><td>{_pills(result.get("matched_rules", []))}</td></tr>
      <tr><td>3. Violated rules</td><td>{_pills(result.get("violated_rules", []))}</td></tr>
      <tr><td>4. Reason codes</td><td>{_pills(result.get("reason_codes", []))}</td></tr>
      <tr><td>5. Actions</td><td>{_pills(result.get("actions", []))}</td></tr>
      <tr><td>6. Remediation</td><td>{_pills(result.get("remediation", []))}</td></tr>
    </table>
    <h3>Reason</h3><pre>{escape(str(result.get("reason", "-")))}</pre>
    <h3>Model-Safe Output</h3><pre>{escape(str(result.get("content", "-")))}</pre>
    """


def _empty_result() -> str:
    return "<p>Paste a prompt or multi-step agent trajectory, then run the simulation.</p>"


def _pills(values: Any) -> str:
    items = values if isinstance(values, list) else [values]
    return "".join(f'<span class="pill">{escape(str(item))}</span>' for item in items) or "-"


def _open_browser(host: str, port: int) -> None:
    import webbrowser

    webbrowser.open(f"http://{host}:{port}")
