from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from policyaware.models import AuditTrace, GatewayRequest, GatewayResponse


def estimate_tokens(text: str) -> int:
    return max(1, len(text.split()))


class AuditLogger:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None

    def record(self, request: GatewayRequest, response: GatewayResponse, started_at: float) -> AuditTrace:
        input_tokens = estimate_tokens(request.prompt_text)
        output_tokens = estimate_tokens(response.content)
        model = response.route.model if response.route else None
        trace = AuditTrace(
            trace_id=response.trace_id,
            request_id=request.request_id,
            tenant=request.tenant,
            app=request.app,
            user_id=request.user.get("id"),
            task_type=request.context.get("task_type"),
            policy_decision=response.policy.decision.value,
            matched_rules=response.policy.matched_rules,
            reason_codes=response.policy.reason_codes,
            actions=response.policy.actions,
            risk_tier=response.policy.risk_tier.value,
            model=model.name if model else None,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost_usd=((input_tokens + output_tokens) / 1000)
            * (model.cost_per_1k_tokens if model else 0),
            latency_ms=int((time.perf_counter() - started_at) * 1000),
            risk_score=response.policy.risk_score,
            eval_scores={result.name: result.score for result in response.evals},
            request_snapshot=request.model_dump(mode="json"),
            response_snapshot={
                "content": response.content,
                "policy": response.policy.model_dump(mode="json"),
                "route": response.route.model_dump(mode="json") if response.route else None,
                "evals": [result.model_dump(mode="json") for result in response.evals],
            },
        )
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(trace.model_dump_json() + "\n")
        return trace

    def export_jsonl(self, traces: list[AuditTrace], path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as handle:
            for trace in traces:
                handle.write(json.dumps(trace.model_dump(mode="json")) + "\n")

    def read_traces(self) -> list[dict[str, Any]]:
        if not self.path or not self.path.exists():
            return []
        traces: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    traces.append(json.loads(line))
        return traces

    def find_trace(self, trace_id: str) -> dict[str, Any] | None:
        for trace in self.read_traces():
            if trace.get("trace_id") == trace_id:
                return trace
        return None


class SQLiteAuditLogger(AuditLogger):
    def __init__(self, path: str | Path = ".policyaware/audit.db"):
        super().__init__(None)
        self.db_path = Path(path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS traces (
                    trace_id TEXT PRIMARY KEY,
                    tenant TEXT NOT NULL,
                    app TEXT NOT NULL,
                    policy_decision TEXT NOT NULL,
                    risk_tier TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    trace_json TEXT NOT NULL
                )
                """
            )

    def record(self, request: GatewayRequest, response: GatewayResponse, started_at: float) -> AuditTrace:
        trace = super().record(request, response, started_at)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO traces
                    (trace_id, tenant, app, policy_decision, risk_tier, created_at, trace_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    trace.trace_id,
                    trace.tenant,
                    trace.app,
                    trace.policy_decision,
                    trace.risk_tier,
                    trace.created_at.isoformat(),
                    trace.model_dump_json(),
                ),
            )
        return trace

    def read_traces(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT trace_json FROM traces ORDER BY created_at DESC").fetchall()
        return [json.loads(row[0]) for row in rows]

    def find_trace(self, trace_id: str) -> dict[str, Any] | None:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT trace_json FROM traces WHERE trace_id = ?", (trace_id,)).fetchone()
        return json.loads(row[0]) if row else None


class TraceViewer:
    def write_html(self, traces: list[dict[str, Any]], path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        rows = "\n".join(
            "<tr>"
            f"<td>{trace.get('trace_id')}</td>"
            f"<td>{trace.get('tenant')}</td>"
            f"<td>{trace.get('app')}</td>"
            f"<td>{trace.get('policy_decision')}</td>"
            f"<td>{trace.get('risk_tier')}</td>"
            f"<td>{trace.get('model') or '-'}</td>"
            f"<td>{trace.get('latency_ms')}</td>"
            f"<td>{', '.join(trace.get('reason_codes', []))}</td>"
            "</tr>"
            for trace in traces
        )
        html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PolicyAware Trace Viewer</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #1f2933; }}
    h1 {{ color: #1f4e79; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
    th {{ background: #1f4e79; color: white; text-align: left; }}
    th, td {{ border: 1px solid #d0d7de; padding: 8px; vertical-align: top; }}
    tr:nth-child(even) {{ background: #f6f8fa; }}
  </style>
</head>
<body>
  <h1>PolicyAware Trace Viewer</h1>
  <p>Static audit trace view generated from local audit storage.</p>
  <table>
    <thead>
      <tr>
        <th>Trace</th><th>Tenant</th><th>App</th><th>Decision</th>
        <th>Risk</th><th>Model</th><th>Latency ms</th><th>Reason Codes</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>
"""
        output.write_text(html, encoding="utf-8")
        return output


class AuditBundleWriter:
    def write(self, trace: dict[str, Any], output_dir: str | Path) -> list[Path]:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        files = {
            "trace.json": trace,
            "decision.json": trace.get("response_snapshot", {}).get("policy", {}),
            "request.json": trace.get("request_snapshot", {}),
            "eval_report.json": trace.get("response_snapshot", {}).get("evals", []),
            "summary.md": self._summary(trace),
        }
        written: list[Path] = []
        for name, content in files.items():
            path = output / name
            with path.open("w", encoding="utf-8") as handle:
                if name.endswith(".md"):
                    handle.write(str(content))
                else:
                    json.dump(content, handle, indent=2)
            written.append(path)
        return written

    def _summary(self, trace: dict[str, Any]) -> str:
        return "\n".join(
            [
                f"# PolicyAware Audit Summary",
                "",
                f"- Trace: `{trace.get('trace_id')}`",
                f"- Tenant: `{trace.get('tenant')}`",
                f"- Decision: `{trace.get('policy_decision')}`",
                f"- Risk tier: `{trace.get('risk_tier')}`",
                f"- Reason codes: `{', '.join(trace.get('reason_codes', [])) or '-'}`",
                f"- Model: `{trace.get('model') or '-'}`",
                f"- Latency: `{trace.get('latency_ms')} ms`",
            ]
        )
