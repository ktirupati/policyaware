from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path
from typing import Any


class GovernanceDashboard:
    """Static HTML dashboard for audit traces."""

    def write_html(self, traces: list[dict[str, Any]], path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        decisions = Counter(trace.get("policy_decision", "unknown") for trace in traces)
        risks = Counter(trace.get("risk_tier", "unknown") for trace in traces)
        apps = Counter(trace.get("app", "unknown") for trace in traces)
        total_cost = sum(float(trace.get("estimated_cost_usd", 0.0) or 0.0) for trace in traces)
        avg_latency = (
            sum(int(trace.get("latency_ms", 0) or 0) for trace in traces) / len(traces)
            if traces
            else 0
        )
        rows = "\n".join(
            "<tr>"
            f"<td>{escape(str(trace.get('created_at', '-')))}</td>"
            f"<td>{escape(str(trace.get('trace_id', '-')))}</td>"
            f"<td>{escape(str(trace.get('parent_trace_id') or '-'))}</td>"
            f"<td>{escape(str(trace.get('session_id') or '-'))}</td>"
            f"<td>{escape(str(trace.get('app', '-')))}</td>"
            f"<td>{escape(str(trace.get('policy_decision', '-')))}</td>"
            f"<td>{escape(str(trace.get('risk_tier', '-')))}</td>"
            f"<td>{escape(', '.join(trace.get('reason_codes', [])))}</td>"
            "</tr>"
            for trace in traces[:500]
        )
        html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PolicyAware Governance Dashboard</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #1f2933; }}
    h1 {{ color: #1f4e79; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }}
    .card {{ border: 1px solid #d0d7de; padding: 14px; border-radius: 6px; background: #f6f8fa; }}
    .metric {{ font-size: 24px; font-weight: 700; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
    th {{ background: #1f4e79; color: white; text-align: left; }}
    th, td {{ border: 1px solid #d0d7de; padding: 8px; vertical-align: top; }}
    tr:nth-child(even) {{ background: #f6f8fa; }}
    pre {{ white-space: pre-wrap; }}
  </style>
</head>
<body>
  <h1>PolicyAware Governance Dashboard</h1>
  <div class="grid">
    <div class="card"><div class="metric">{len(traces)}</div><div>Total traces</div></div>
    <div class="card"><div class="metric">${total_cost:.4f}</div><div>Estimated cost</div></div>
    <div class="card"><div class="metric">{avg_latency:.1f} ms</div><div>Average latency</div></div>
    <div class="card"><div class="metric">{decisions.get('deny', 0)}</div><div>Denied requests</div></div>
  </div>
  <div class="grid">
    <div class="card"><h3>Decisions</h3><pre>{escape(_counter_text(decisions))}</pre></div>
    <div class="card"><h3>Risk Tiers</h3><pre>{escape(_counter_text(risks))}</pre></div>
    <div class="card"><h3>Top Apps</h3><pre>{escape(_counter_text(apps, limit=8))}</pre></div>
    <div class="card"><h3>Integrity</h3><pre>{_integrity_count(traces)} signed traces</pre></div>
  </div>
  <h2>Recent Traces</h2>
  <table>
    <thead>
      <tr><th>Created</th><th>Trace</th><th>Parent</th><th>Session</th><th>App</th><th>Decision</th><th>Risk</th><th>Reason Codes</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>
"""
        output.write_text(html, encoding="utf-8")
        return output


def _counter_text(counter: Counter, *, limit: int = 10) -> str:
    return "\n".join(f"{key}: {value}" for key, value in counter.most_common(limit)) or "-"


def _integrity_count(traces: list[dict[str, Any]]) -> int:
    return sum(1 for trace in traces if "integrity" in trace)

