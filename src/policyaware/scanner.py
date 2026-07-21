from __future__ import annotations

import html
import json
import os
import re
import subprocess
import time
import webbrowser
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from fnmatch import fnmatch
from hashlib import sha256
from pathlib import Path
from typing import Iterable

from policyaware.data_protection import DataProtectionEngine
from policyaware.policy_schema import PolicySchemaValidator, PolicyValidationError


@dataclass(frozen=True)
class ScanFinding:
    severity: str
    category: str
    file: str
    line: int
    title: str
    evidence: str
    recommendation: str
    docs_url: str
    fingerprint: str = ""
    compliance_area: str = ""
    fix_snippet: str = ""


@dataclass(frozen=True)
class ScanFileResult:
    path: str
    findings: list[ScanFinding] = field(default_factory=list)


@dataclass
class ScanReport:
    scanned_path: str
    output_path: str
    generated_at: str
    duration_seconds: float
    files_scanned: int
    files_skipped: int
    findings: list[ScanFinding]
    baseline_ignored: int = 0
    policy_coverage_score: int = 100
    policy_coverage_missing: list[str] = field(default_factory=list)
    suppressed_findings: int = 0
    scanned_files: list[str] = field(default_factory=list)

    @property
    def severity_counts(self) -> Counter[str]:
        return Counter(finding.severity for finding in self.findings)

    @property
    def category_counts(self) -> Counter[str]:
        return Counter(finding.category for finding in self.findings)

    @property
    def overall_risk(self) -> str:
        counts = self.severity_counts
        if counts["critical"]:
            return "Critical"
        if counts["high"]:
            return "High"
        if counts["medium"]:
            return "Medium"
        if counts["low"]:
            return "Low"
        return "Clean"

    def to_dict(self) -> dict[str, object]:
        return {
            "scanned_path": self.scanned_path,
            "output_path": self.output_path,
            "generated_at": self.generated_at,
            "duration_seconds": round(self.duration_seconds, 4),
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "baseline_ignored": self.baseline_ignored,
            "suppressed_findings": self.suppressed_findings,
            "overall_risk": self.overall_risk,
            "policy_coverage_score": self.policy_coverage_score,
            "policy_coverage_missing": self.policy_coverage_missing,
            "governance_posture": _governance_posture(self),
            "compliance_counts": dict(self.compliance_counts),
            "compliance_framework_mapping": _compliance_framework_mapping(self),
            "severity_counts": dict(self.severity_counts),
            "category_counts": dict(self.category_counts),
            "scanned_files": self.scanned_files,
            "findings": [asdict(finding) for finding in self.findings],
        }

    @property
    def compliance_counts(self) -> Counter[str]:
        return Counter(finding.compliance_area for finding in self.findings)


@dataclass(frozen=True)
class ScanConfig:
    """User-tunable local scan controls."""

    enabled_categories: frozenset[str] | None = None
    disabled_categories: frozenset[str] = frozenset()
    severity_overrides: dict[str, str] = field(default_factory=dict)
    include_extensions: tuple[str, ...] | None = None
    exclude_dirs: tuple[str, ...] = ()
    ignore_patterns: tuple[str, ...] = ()
    max_file_size_bytes: int | None = None
    max_findings_per_file: int | None = None

    @classmethod
    def from_file(cls, path: Path) -> "ScanConfig":
        import yaml

        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        scan = raw.get("scan", raw)
        if not isinstance(scan, dict):
            return cls()
        return cls(
            enabled_categories=_optional_frozenset(scan.get("enabled_categories")),
            disabled_categories=frozenset(str(item) for item in scan.get("disabled_categories", []) or []),
            severity_overrides={
                str(category): str(severity).lower()
                for category, severity in (scan.get("severity_overrides", {}) or {}).items()
                if str(severity).lower() in {"critical", "high", "medium", "low"}
            },
            include_extensions=tuple(str(item) for item in scan.get("include_extensions", []) or ()) or None,
            exclude_dirs=tuple(str(item) for item in scan.get("exclude_dirs", []) or ()),
            ignore_patterns=tuple(str(item) for item in scan.get("ignore_patterns", []) or ()),
            max_file_size_bytes=_parse_config_size(scan.get("max_file_size")),
            max_findings_per_file=(
                int(scan["max_findings_per_file"]) if scan.get("max_findings_per_file") else None
            ),
        )


class LocalCodeScanner:
    """Fast local governance scanner for source trees.

    The scanner intentionally uses local rule-based checks only. It does not call
    external services, load ML models, or execute project code.
    """

    DEFAULT_EXTENSIONS = {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".yml",
        ".yaml",
        ".json",
        ".md",
        ".txt",
        ".env",
        ".example",
        ".sample",
        ".properties",
        ".toml",
        ".ini",
        ".ipynb",
        ".sql",
        ".tf",
        ".hcl",
        ".dockerfile",
        ".gradle",
        ".java",
        ".scala",
        ".kt",
        ".go",
        ".rs",
        ".sh",
    }
    DEFAULT_EXCLUDED_DIRS = {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "build",
        "target",
        "vendor",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".tox",
        ".next",
        ".nuxt",
        "coverage",
        ".coverage",
        ".cache",
        ".policyaware",
    }
    DEFAULT_MAX_FILE_SIZE_BYTES = 512 * 1024
    DEFAULT_MAX_FINDINGS_PER_FILE = 20

    SECRET_ASSIGNMENT_RE = re.compile(
        r"""(?ix)
        \b(api[_-]?key|secret|token|password|access[_-]?key|private[_-]?key)\b
        \s*[:=]\s*
        ['"]?([A-Za-z0-9_./+=\-]{12,})['"]?
        """
    )
    DIRECT_MODEL_CALL_RE = re.compile(
        r"""(?ix)
        \b(
            openai\.|
            anthropic\.|
            boto3\.client\(['"]bedrock|
            bedrock-runtime|
            vertexai\.|
            generativeai\.|
            litellm\.completion|
            ollama\.(chat|generate)|
            requests\.(post|request)\([^)]*/v1/(chat/)?completions|
            llama_index|
            dspy\.|
            semantic_kernel|
            ChatOpenAI\(|AzureChatOpenAI\(|Anthropic\(|ChatAnthropic\(
        )
        """
    )
    SPARK_PIPELINE_RE = re.compile(
        r"""(?ix)
        \b(
            spark\.read|spark\.sql|readStream|writeStream|saveAsTable|
            \.write\.|write\.format|DataFrameWriter|pyspark|SparkSession|
            dbutils\.fs|s3://|abfss://|wasbs://|gs://|delta\.
        )\b
        """
    )
    PII_COLUMN_RE = re.compile(
        r"""(?ix)
        \b(
            email|e_mail|phone|mobile|ssn|social_security|dob|date_of_birth|
            patient|patient_id|member_id|mrn|medical_record|credit_card|card_number|
            account_number|address|zip|postal_code
        )\b
        """
    )
    PROVIDER_RE = re.compile(
        r"""(?ix)
        \b(
            openai|azure[_-]?openai|anthropic|bedrock|vertexai|gemini|
            ollama|vllm|litellm|llama_index|dspy|semantic_kernel
        )\b
        """
    )
    REGION_ENDPOINT_RE = re.compile(
        r"""(?ix)
        \b(region|location|endpoint|base_url|api_base|api_endpoint|aws_region|azure_endpoint)\b
        \s*[:=]\s*['"]?([^'"\s,}]+)
        """
    )
    EXTERNAL_ENDPOINT_RE = re.compile(
        r"""(?ix)
        https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[A-Za-z0-9_.:/?=&%+-]+
        """
    )
    AUTONOMOUS_LOOP_RE = re.compile(
        r"""(?ix)
        \b(while\s+true|for\s+.*\s+in\s+range\(|max_iterations\s*=\s*None|auto[_-]?execute|autonomous|run_forever|agent\.run)\b
        """
    )
    BUDGET_RE = re.compile(r"\b(max_tokens|token_budget|budget|max_cost|rate_limit|timeout|max_iterations)\b", re.I)
    RAG_METADATA_RE = re.compile(r"\b(source|metadata|document_id|chunk_id|citation|reference|url)\b", re.I)
    CONFIG_SECRET_CONTEXT_RE = re.compile(
        r"""(?ix)
        \b(
            connectionstring|connection_string|client_secret|private_key|secretKeyRef|
            configmap|kubernetes_secret|terraform|TF_VAR_|dockerfile|GITHUB_TOKEN|
            AZURE_CLIENT_SECRET|AWS_SECRET_ACCESS_KEY|GOOGLE_APPLICATION_CREDENTIALS
        )\b
        """
    )
    TOOL_RISK_RE = re.compile(
        r"""(?ix)
        \b(delete|drop|destroy|remove|write|create_pull|create_pr|merge|deploy|refund|payment|transfer)\b
        """
    )
    AGENT_TOOL_RE = re.compile(
        r"""(?ix)
        (
            (?<!\w)@tool\b|
            \bmcp\.tool\b|\bmcp_server\b|\bFastMCP\b|\bTool\(|\bStructuredTool\b|
            \bcrewai\.tools\b|\bautogen\b|\bregister_function\b|\bfunction_call\b|\btool_calls\b
        )
        """
    )
    PROMPT_RISK_RE = re.compile(
        r"""(?ix)
        \b(
            ignore\s+(all\s+)?previous\s+instructions|
            disregard\s+(all\s+)?previous\s+instructions|
            disable\s+safety|
            bypass\s+(policy|guardrails?|safety)|
            reveal\s+(the\s+)?(system\s+)?prompt|
            do\s+not\s+follow\s+(policy|rules)|
            act\s+autonomously|
            execute\s+without\s+approval
        )\b
        """
    )
    RAG_RE = re.compile(r"\b(vectorstore|retriever|similarity_search|rag|retrieve|embedding)\b", re.I)
    CITATION_RE = re.compile(r"\b(citation|source|grounding|reference)\b", re.I)

    DOCS = {
        "data": "https://github.com/ktirupati/policyaware/blob/main/docs/capabilities/data-protection.md",
        "policy": "https://github.com/ktirupati/policyaware/blob/main/docs/capabilities/policy-enforcement.md",
        "tool": "https://github.com/ktirupati/policyaware/blob/main/docs/capabilities/tool-governance.md",
        "routing": "https://github.com/ktirupati/policyaware/blob/main/docs/capabilities/model-routing-providers.md",
        "eval": "https://github.com/ktirupati/policyaware/blob/main/docs/capabilities/evaluation.md",
        "audit": "https://github.com/ktirupati/policyaware/blob/main/docs/capabilities/audit-observability.md",
        "yaml": "https://github.com/ktirupati/policyaware/blob/main/docs/capabilities/ready-to-use-yaml.md",
    }

    def __init__(
        self,
        *,
        include_extensions: Iterable[str] | None = None,
        exclude_dirs: Iterable[str] | None = None,
        ignore_patterns: Iterable[str] | None = None,
        baseline_fingerprints: Iterable[str] | None = None,
        config: ScanConfig | None = None,
        diff_files: Iterable[str] | None = None,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
        max_findings_per_file: int = DEFAULT_MAX_FINDINGS_PER_FILE,
        workers: int | None = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.include_extensions = {
            ext if ext.startswith(".") else f".{ext}"
            for ext in (
                include_extensions
                or self.config.include_extensions
                or self.DEFAULT_EXTENSIONS
            )
        }
        self.exclude_dirs = set(self.DEFAULT_EXCLUDED_DIRS)
        self.exclude_dirs.update(self.config.exclude_dirs)
        self.exclude_dirs.update(exclude_dirs or [])
        self.ignore_patterns = list(self.config.ignore_patterns)
        self.ignore_patterns.extend(ignore_patterns or [])
        self.baseline_fingerprints = set(baseline_fingerprints or [])
        self.diff_files = {str(item).replace("\\", "/") for item in (diff_files or [])}
        self.max_file_size_bytes = self.config.max_file_size_bytes or max_file_size_bytes
        self.max_findings_per_file = self.config.max_findings_per_file or max_findings_per_file
        self.workers = workers or min((os.cpu_count() or 4), 8)
        self.data_protection = DataProtectionEngine()

    def scan(
        self,
        path: Path,
        *,
        out: Path = Path("policyaware-scan-report.html"),
        json_out: Path | None = None,
        sarif_out: Path | None = None,
        markdown_out: Path | None = None,
        open_report: bool = False,
    ) -> ScanReport:
        started = time.perf_counter()
        root = path.resolve()
        files, skipped = self._discover_files(root)
        findings: list[ScanFinding] = []
        suppressed = 0

        with ThreadPoolExecutor(max_workers=max(self.workers, 1)) as executor:
            futures = [executor.submit(self._scan_file, file_path, root) for file_path in files]
            for future in as_completed(futures):
                findings.extend(future.result().findings)

        findings = [_with_fingerprint(finding) for finding in findings]
        original_findings = len(findings)
        findings = [
            self._apply_config(finding)
            for finding in findings
            if self._is_category_enabled(finding.category)
        ]
        suppressed += original_findings - len(findings)
        baseline_ignored = 0
        if self.baseline_fingerprints:
            original_count = len(findings)
            findings = [
                finding for finding in findings if finding.fingerprint not in self.baseline_fingerprints
            ]
            baseline_ignored = original_count - len(findings)
        findings.sort(key=lambda item: (_severity_rank(item.severity), item.file, item.line))
        duration = time.perf_counter() - started
        coverage_score, coverage_missing = _policy_coverage(findings)
        report = ScanReport(
            scanned_path=str(root),
            output_path=str(out.resolve()),
            generated_at=datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
            duration_seconds=duration,
            files_scanned=len(files),
            files_skipped=skipped,
            findings=findings,
            baseline_ignored=baseline_ignored,
            policy_coverage_score=coverage_score,
            policy_coverage_missing=coverage_missing,
            suppressed_findings=suppressed,
            scanned_files=[str(file.relative_to(root)).replace("\\", "/") for file in files],
        )
        ScanHtmlReportWriter().write(report, out)
        if json_out:
            ScanJsonReportWriter().write(report, json_out)
        if sarif_out:
            ScanSarifReportWriter().write(report, sarif_out)
        if markdown_out:
            ScanMarkdownReportWriter().write(report, markdown_out)
        if open_report:
            webbrowser.open(out.resolve().as_uri())
        return report

    def _discover_files(self, root: Path) -> tuple[list[Path], int]:
        if root.is_file():
            return ([root] if self._should_scan_file(root) else []), 0 if self._should_scan_file(root) else 1

        files: list[Path] = []
        skipped = 0
        for current_root, dirs, names in os.walk(root):
            dirs[:] = [directory for directory in dirs if directory not in self.exclude_dirs]
            skipped += len(names)
            current = Path(current_root)
            for name in names:
                file_path = current / name
                relative = str(file_path.relative_to(root)).replace("\\", "/")
                if self.diff_files and relative not in self.diff_files:
                    continue
                if self._is_ignored(relative):
                    continue
                if self._should_scan_file(file_path):
                    files.append(file_path)
                    skipped -= 1
        return files, max(skipped, 0)

    def _is_ignored(self, relative_path: str) -> bool:
        return any(fnmatch(relative_path, pattern) for pattern in self.ignore_patterns)

    def _is_category_enabled(self, category: str) -> bool:
        if self.config.enabled_categories is not None and category not in self.config.enabled_categories:
            return False
        return category not in self.config.disabled_categories

    def _apply_config(self, finding: ScanFinding) -> ScanFinding:
        severity = self.config.severity_overrides.get(finding.category, finding.severity)
        return replace(finding, severity=severity)

    def _should_scan_file(self, path: Path) -> bool:
        if not path.is_file():
            return False
        if path.name in {"BingSiteAuth.xml"} or path.name.startswith("google") and path.suffix == ".html":
            return False
        suffix = path.suffix.lower()
        if path.name.startswith(".env"):
            suffix = ".env"
        if path.name.lower() == "dockerfile" or path.name.lower().endswith(".dockerfile"):
            suffix = ".dockerfile"
        if suffix not in self.include_extensions:
            return False
        try:
            return path.stat().st_size <= self.max_file_size_bytes
        except OSError:
            return False

    def _scan_file(self, path: Path, root: Path) -> ScanFileResult:
        relative = str(path.relative_to(root))
        try:
            text = _read_scan_text(path)
        except OSError:
            return ScanFileResult(path=relative)

        findings: list[ScanFinding] = []
        if _has_file_suppression(text):
            return ScanFileResult(path=relative)
        suppressed_lines = _suppressed_lines(text)
        has_policyaware = _has_policyaware_gateway(text)
        lowered_text = text.lower()
        has_approval = ("require_approval" in lowered_text or "approval_required" in lowered_text) or (
            "approval" in lowered_text and "without approval" not in lowered_text
        )
        has_audit = "audit" in text.lower() or "trace" in text.lower()
        has_citation = bool(self.CITATION_RE.search(text))
        has_budget = bool(self.BUDGET_RE.search(text))
        has_region_policy = "region" in text.lower() and (
            "policyaware" in text.lower() or "allowed" in text.lower() or "approved" in text.lower()
        )

        for line_number, line in enumerate(text.splitlines(), start=1):
            if len(findings) >= self.max_findings_per_file:
                break
            stripped = line.strip()
            if not stripped or _looks_like_comment_only(stripped):
                continue
            if line_number in suppressed_lines:
                continue
            findings.extend(self._scan_line(relative, line_number, stripped, has_policyaware))
            if len(findings) >= self.max_findings_per_file:
                break

        if (
            self.DIRECT_MODEL_CALL_RE.search(text)
            and not has_policyaware
            and not any(finding.category == "LLM Governance" for finding in findings)
        ):
            findings.append(
                ScanFinding(
                    severity="high",
                    category="LLM Governance",
                    file=relative,
                    line=_first_match_line(text, self.DIRECT_MODEL_CALL_RE),
                    title="Direct model call may bypass PolicyAware",
                    evidence="Direct provider or framework model call detected.",
                    recommendation=(
                        "Route prompts through PolicyAware Gateway before model execution so PII, "
                        "secrets, policy, risk, routing, evaluation, and audit checks run consistently."
                    ),
                    docs_url=self.DOCS["policy"],
                )
            )
        if self.TOOL_RISK_RE.search(text) and not has_approval and _is_code_file(path):
            findings.append(
                ScanFinding(
                    severity="high",
                    category="Tool Governance",
                    file=relative,
                    line=_first_match_line(text, self.TOOL_RISK_RE),
                    title="Risky tool/action words found without approval language",
                    evidence="Potential write/delete/deploy/refund style action detected.",
                    recommendation=(
                        "Add connector/action policy and require approval for high-impact tool actions."
                    ),
                    docs_url=self.DOCS["tool"],
                )
            )
        if self.PROVIDER_RE.search(text) and not has_policyaware and _is_code_file(path):
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="Provider Governance",
                    file=relative,
                    line=_first_match_line(text, self.PROVIDER_RE),
                    title="Model provider usage found outside PolicyAware routing",
                    evidence="Provider or framework identifier detected in source code.",
                    recommendation=(
                        "Register providers in PolicyAware and route by policy, risk, role, region, "
                        "cost, and availability instead of calling providers directly."
                    ),
                    docs_url=self.DOCS["routing"],
                )
            )
        if (self.REGION_ENDPOINT_RE.search(text) or self.EXTERNAL_ENDPOINT_RE.search(text)) and not has_region_policy:
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="Data Residency",
                    file=relative,
                    line=min(
                        _first_match_line(text, self.REGION_ENDPOINT_RE),
                        _first_match_line(text, self.EXTERNAL_ENDPOINT_RE),
                    ),
                    title="Region or external endpoint found without obvious policy constraint",
                    evidence="Endpoint, base URL, region, or cloud location detected.",
                    recommendation=(
                        "Add region, tenant, and compliance constraints to policy and route regulated "
                        "traffic only to approved providers or local models."
                    ),
                    docs_url=self.DOCS["routing"],
                )
            )
        if self.AGENT_TOOL_RE.search(text) and not has_approval and _is_code_file(path):
            findings.append(
                ScanFinding(
                    severity="high",
                    category="Agent Tool Governance",
                    file=relative,
                    line=_first_match_line(text, self.AGENT_TOOL_RE),
                    title="Agent/tool framework usage found without approval language",
                    evidence="Tool registration, function calling, MCP, or agent tool usage detected.",
                    recommendation=(
                        "Add PolicyAware tool governance for connector-level and action-level permissions, "
                        "and require approval for sensitive tool actions."
                    ),
                    docs_url=self.DOCS["tool"],
                )
            )
        if self.AUTONOMOUS_LOOP_RE.search(text) and not has_approval and _is_code_file(path):
            findings.append(
                ScanFinding(
                    severity="high",
                    category="Autonomous Agent Governance",
                    file=relative,
                    line=_first_match_line(text, self.AUTONOMOUS_LOOP_RE),
                    title="Autonomous loop or auto-execution pattern found without approval guard",
                    evidence="Looping, autonomous, or auto-execute agent behavior detected.",
                    recommendation=(
                        "Add max-iteration, budget, approval, and audit controls before autonomous "
                        "agent execution or tool use."
                    ),
                    docs_url=self.DOCS["tool"],
                )
            )
        if (self.DIRECT_MODEL_CALL_RE.search(text) or self.AGENT_TOOL_RE.search(text)) and not has_budget:
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="Cost Governance",
                    file=relative,
                    line=min(
                        _first_match_line(text, self.DIRECT_MODEL_CALL_RE),
                        _first_match_line(text, self.AGENT_TOOL_RE),
                    ),
                    title="Model or agent execution found without obvious budget/rate controls",
                    evidence="Model or agent usage detected, but no token/cost/rate/iteration control found.",
                    recommendation=(
                        "Add token, cost, timeout, rate-limit, and max-iteration controls to prevent "
                        "runaway model or agent execution."
                    ),
                    docs_url=self.DOCS["routing"],
                )
            )
        if self.RAG_RE.search(text) and not has_citation and _is_code_file(path):
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="RAG Governance",
                    file=relative,
                    line=_first_match_line(text, self.RAG_RE),
                    title="RAG or retrieval code found without citation/grounding language",
                    evidence="Retrieval or embedding workflow detected.",
                    recommendation=(
                        "Add citation and grounding checks to runtime evaluation for RAG answers."
                    ),
                    docs_url=self.DOCS["eval"],
                )
            )
        if self.SPARK_PIPELINE_RE.search(text) and _is_code_file(path):
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="Data Pipeline Governance",
                    file=relative,
                    line=_first_match_line(text, self.SPARK_PIPELINE_RE),
                    title="Spark or data pipeline operation detected",
                    evidence="Spark, streaming, cloud path, or table write operation detected.",
                    recommendation=(
                        "Check sensitive columns before writes, add masking/redaction, and record audit "
                        "metadata for governed data pipelines."
                    ),
                    docs_url=self.DOCS["data"],
                )
            )
        if self.RAG_RE.search(text) and not self.RAG_METADATA_RE.search(text) and _is_code_file(path):
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="RAG Governance",
                    file=relative,
                    line=_first_match_line(text, self.RAG_RE),
                    title="RAG code found without source metadata language",
                    evidence="Retrieval workflow detected, but no obvious source/chunk/document metadata handling.",
                    recommendation=(
                        "Preserve source metadata, document IDs, chunk IDs, and citation fields so "
                        "answers can be grounded and audited."
                    ),
                    docs_url=self.DOCS["eval"],
                )
            )
        if self.SPARK_PIPELINE_RE.search(text) and self.PII_COLUMN_RE.search(text) and _is_code_file(path):
            findings.append(
                ScanFinding(
                    severity="high",
                    category="Data Pipeline Governance",
                    file=relative,
                    line=min(
                        _first_match_line(text, self.SPARK_PIPELINE_RE),
                        _first_match_line(text, self.PII_COLUMN_RE),
                    ),
                    title="Sensitive-looking data column used in Spark/data pipeline code",
                    evidence="PII/PHI-like column names appear near data pipeline code.",
                    recommendation=(
                        "Classify and mask sensitive columns before writing to tables, object storage, "
                        "logs, or model/RAG inputs."
                    ),
                    docs_url=self.DOCS["data"],
                )
            )
        if self.DIRECT_MODEL_CALL_RE.search(text) and not has_audit and _is_code_file(path):
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="Auditability",
                    file=relative,
                    line=_first_match_line(text, self.DIRECT_MODEL_CALL_RE),
                    title="Model execution found without audit/trace language",
                    evidence="Model call detected, but no obvious audit or trace handling in this file.",
                    recommendation="Capture request, decision, route, response, and evaluation trace data.",
                    docs_url=self.DOCS["audit"],
                )
            )
        if self.CONFIG_SECRET_CONTEXT_RE.search(text) and _is_config_file(path):
            findings.append(
                ScanFinding(
                    severity="high",
                    category="Configuration Governance",
                    file=relative,
                    line=_first_match_line(text, self.CONFIG_SECRET_CONTEXT_RE),
                    title="Sensitive configuration or infrastructure secret context detected",
                    evidence="Secret/config/IaC keyword detected in configuration-style file.",
                    recommendation=(
                        "Use secret-manager references, avoid plaintext credentials, and validate that "
                        "CI/CD, Kubernetes, Docker, Terraform, and env files do not expose secrets."
                    ),
                    docs_url=self.DOCS["data"],
                )
            )
        if path.suffix.lower() in {".yaml", ".yml"}:
            findings.extend(self._scan_yaml_policy(path, relative))

        findings = [finding for finding in findings if finding.line not in suppressed_lines]
        trimmed = findings[: self.max_findings_per_file]
        return ScanFileResult(path=relative, findings=trimmed)

    def _scan_line(
        self,
        relative: str,
        line_number: int,
        line: str,
        has_policyaware: bool,
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        data = self.data_protection.inspect(line)
        if data.contains_secrets or self.SECRET_ASSIGNMENT_RE.search(line):
            findings.append(
                ScanFinding(
                    severity="critical",
                    category="Secrets",
                    file=relative,
                    line=line_number,
                    title="Possible secret or API credential found",
                    evidence=_redact_evidence(line),
                    recommendation=(
                        "Move credentials to environment variables or a secret manager. Rotate exposed keys "
                        "if this file has been committed or shared."
                    ),
                    docs_url=self.DOCS["data"],
                )
            )
        elif data.contains_phi:
            findings.append(
                ScanFinding(
                    severity="high",
                    category="PHI",
                    file=relative,
                    line=line_number,
                    title="Possible protected health information found",
                    evidence=_redact_evidence(line),
                    recommendation=(
                        "Avoid storing PHI in prompts, fixtures, or logs. Use PolicyAware redaction and "
                        "regulated-domain policies before model execution."
                    ),
                    docs_url=self.DOCS["data"],
                )
            )
        elif data.contains_pii:
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="PII",
                    file=relative,
                    line=line_number,
                    title="Possible personal data found",
                    evidence=_redact_evidence(line),
                    recommendation=(
                        "Redact or tokenize PII before sending prompts to models, tools, logs, or test reports."
                    ),
                    docs_url=self.DOCS["data"],
                )
            )

        if self.DIRECT_MODEL_CALL_RE.search(line) and not has_policyaware:
            findings.append(
                ScanFinding(
                    severity="high",
                    category="LLM Governance",
                    file=relative,
                    line=line_number,
                    title="Direct LLM provider call detected",
                    evidence=_redact_evidence(line),
                    recommendation="Wrap this call with PolicyAware Gateway to enforce policy before execution.",
                    docs_url=self.DOCS["policy"],
                )
            )
        if self.PROMPT_RISK_RE.search(line):
            findings.append(
                ScanFinding(
                    severity="high",
                    category="Prompt Safety",
                    file=relative,
                    line=line_number,
                    title="Risky prompt-instruction language detected",
                    evidence=_redact_evidence(line),
                    recommendation=(
                        "Review prompt templates for injection-prone or policy-bypass instructions. "
                        "Add runtime prompt checks and require approval for autonomous actions."
                    ),
                    docs_url=self.DOCS["policy"],
                )
            )
        return findings

    def _scan_yaml_policy(self, path: Path, relative: str) -> list[ScanFinding]:
        try:
            import yaml

            with path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except Exception:
            return []

        if not isinstance(data, dict) or "rules" not in data:
            return []

        findings: list[ScanFinding] = []
        try:
            PolicySchemaValidator().validate(data)
        except PolicyValidationError as exc:
            findings.append(
                ScanFinding(
                    severity="high",
                    category="Policy YAML",
                    file=relative,
                    line=1,
                    title="Policy schema validation failed",
                    evidence="; ".join(exc.errors[:3]),
                    recommendation="Fix policy schema errors before relying on this policy in runtime flows.",
                    docs_url=self.DOCS["yaml"],
                )
            )
        if data.get("default") != "deny":
            findings.append(
                ScanFinding(
                    severity="medium",
                    category="Policy YAML",
                    file=relative,
                    line=1,
                    title="Policy is not deny-by-default",
                    evidence=f"default: {data.get('default', '<missing>')}",
                    recommendation="Use `default: deny` so requests are blocked unless explicitly allowed.",
                    docs_url=self.DOCS["policy"],
                )
            )
        return findings


class ScanHtmlReportWriter:
    """Render a standalone, user-friendly HTML scan report."""

    def write(self, report: ScanReport, out: Path) -> Path:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.render(report), encoding="utf-8")
        return out

    def render(self, report: ScanReport) -> str:
        counts = report.severity_counts
        categories = report.category_counts
        compliance_areas = report.compliance_counts
        by_file: dict[str, list[ScanFinding]] = defaultdict(list)
        for finding in report.findings:
            by_file[finding.file].append(finding)

        rows = "\n".join(_finding_row(finding) for finding in report.findings) or (
            "<tr><td colspan='7' class='empty'>No findings detected in fast scan.</td></tr>"
        )
        file_sections = "\n".join(
            _file_section(file, findings) for file, findings in sorted(by_file.items())
        ) or "<p class='empty'>No file-level findings detected.</p>"
        category_chips = "\n".join(
            f"<span class='chip'>{html.escape(category)} <strong>{count}</strong></span>"
            for category, count in categories.most_common()
        ) or "<span class='chip'>No findings</span>"

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PolicyAware Local Code Scan Report</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --panel: #ffffff;
      --text: #162033;
      --muted: #5d6a7e;
      --line: #dfe5ef;
      --critical: #b42318;
      --high: #c2410c;
      --medium: #a16207;
      --low: #2563eb;
      --clean: #15803d;
      --accent: #0f766e;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    header {{
      background: #102033;
      color: white;
      padding: 32px 40px;
    }}
    header h1 {{ margin: 0 0 8px; font-size: 30px; }}
    header p {{ margin: 4px 0; color: #d9e2ef; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px 20px 48px; }}
    .cards {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 14px; }}
    .card, section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      box-shadow: 0 1px 2px rgba(16, 32, 51, 0.04);
    }}
    .card {{ padding: 18px; }}
    .label {{ color: var(--muted); font-size: 13px; }}
    .value {{ font-size: 28px; font-weight: 750; margin-top: 4px; }}
    section {{ margin-top: 20px; padding: 22px; }}
    h2 {{ margin: 0 0 14px; font-size: 22px; }}
    h3 {{ margin: 18px 0 8px; }}
    .risk {{ color: {_risk_color(report.overall_risk)}; }}
    .grid-two {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }}
    .recommendations li {{ margin: 8px 0; }}
    .chip {{
      display: inline-flex;
      gap: 8px;
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 7px 11px;
      margin: 4px;
      background: #f8fafc;
      color: #26364d;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }}
    th {{ font-size: 13px; color: var(--muted); background: #f8fafc; }}
    code {{
      background: #eef2f7;
      border: 1px solid #d8e0eb;
      border-radius: 5px;
      padding: 2px 5px;
      font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
    }}
    pre {{
      background: #0b1220;
      color: #e5eefc;
      border-radius: 8px;
      overflow: auto;
      padding: 14px;
    }}
    .sev {{
      display: inline-block;
      min-width: 78px;
      text-align: center;
      border-radius: 999px;
      padding: 4px 9px;
      color: white;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .sev-critical {{ background: var(--critical); }}
    .sev-high {{ background: var(--high); }}
    .sev-medium {{ background: var(--medium); }}
    .sev-low {{ background: var(--low); }}
    details {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px 14px;
      margin: 10px 0;
      background: #fbfdff;
    }}
    summary {{ cursor: pointer; font-weight: 700; }}
    .muted {{ color: var(--muted); }}
    .empty {{ color: var(--muted); text-align: center; padding: 20px; }}
    a {{ color: #075985; }}
    .filters {{
      display: grid;
      grid-template-columns: 1fr 180px 220px 240px;
      gap: 10px;
      margin: 12px 0 16px;
    }}
    .filters input, .filters select {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px 12px;
      font: inherit;
      background: white;
    }}
    .hidden-row {{ display: none; }}
    @media (max-width: 900px) {{
      .cards, .grid-two, .filters {{ grid-template-columns: 1fr; }}
      header {{ padding: 24px 20px; }}
      table {{ font-size: 14px; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>PolicyAware Local Code Scan Report</h1>
    <p>Fast local governance scan for AI application code. No network, no model calls, no project execution.</p>
    <p><strong>Scanned path:</strong> {html.escape(report.scanned_path)}</p>
    <p><strong>Generated:</strong> {html.escape(report.generated_at)}</p>
  </header>
  <main>
    <div class="cards">
      <div class="card"><div class="label">Overall Risk</div><div class="value risk">{html.escape(report.overall_risk)}</div></div>
      <div class="card"><div class="label">Files Scanned</div><div class="value">{report.files_scanned}</div></div>
      <div class="card"><div class="label">Findings</div><div class="value">{len(report.findings)}</div></div>
      <div class="card"><div class="label">Scan Time</div><div class="value">{report.duration_seconds:.2f}s</div></div>
      <div class="card"><div class="label">Policy Coverage</div><div class="value">{report.policy_coverage_score}%</div></div>
    </div>

    <section>
      <h2>Executive Summary</h2>
      <div class="grid-two">
        <div>
          <p>This report highlights sensitive-data exposure, secrets, provider usage, direct LLM calls, risky tool actions, RAG governance gaps, data residency issues, data-pipeline risks, policy YAML issues, cost controls, and auditability gaps found in the scanned files.</p>
          <p class="muted">Evidence is redacted so the report can be shared more safely with engineering, security, and compliance reviewers.</p>
        </div>
        <div>
          <span class="chip">Critical <strong>{counts["critical"]}</strong></span>
          <span class="chip">High <strong>{counts["high"]}</strong></span>
          <span class="chip">Medium <strong>{counts["medium"]}</strong></span>
          <span class="chip">Low <strong>{counts["low"]}</strong></span>
          <span class="chip">Skipped files <strong>{report.files_skipped}</strong></span>
          <span class="chip">Baseline ignored <strong>{report.baseline_ignored}</strong></span>
          <span class="chip">Suppressed <strong>{report.suppressed_findings}</strong></span>
        </div>
      </div>
      <h3>Finding Categories</h3>
      <div>{category_chips}</div>
      <h3>Policy Coverage Gaps</h3>
      <p>{_coverage_text(report)}</p>
      <h3>Governance Reviewer Summary</h3>
      <p>{_reviewer_summary(report)}</p>
      <h3>Compliance Areas</h3>
      <div>{_compliance_chips(report)}</div>
    </section>

    <section>
      <h2>Top Recommendations</h2>
      <ol class="recommendations">
        {_recommendations(report)}
      </ol>
    </section>

    <section>
      <h2>Remediation Checklist</h2>
      <ol class="recommendations">
        {_remediation_checklist(report)}
      </ol>
    </section>

    <section>
      <h2>Findings</h2>
      <div class="filters">
        <input id="filterText" type="search" placeholder="Search file, finding, evidence, or recommendation">
        <select id="filterSeverity">
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select id="filterCategory">
          <option value="">All categories</option>
          {_category_options(categories)}
        </select>
        <select id="filterCompliance">
          <option value="">All compliance areas</option>
          {_category_options(compliance_areas)}
        </select>
      </div>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>File</th>
            <th>Line</th>
            <th>Category</th>
            <th>Compliance Area</th>
            <th>Finding</th>
            <th>Recommendation</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>

    <section>
      <h2>Findings By File</h2>
      {file_sections}
    </section>

    <section>
      <h2>Copy-Paste PolicyAware Fix</h2>
      <p>Use the gateway before model calls so prompts and context are checked before execution.</p>
      <pre><code>from policyaware import Gateway, GatewayRequest

gateway = Gateway.from_policy_file("policyaware.yaml")

response = gateway.chat(
    GatewayRequest(
        tenant="acme",
        app="local-ai-app",
        user={{"id": "user_123", "role": "developer"}},
        context={{"region": "us", "risk": "medium", "task_type": "code_assistant"}},
        messages=[{{"role": "user", "content": user_prompt}}],
    )
)

print(response.policy.decision)
print(response.policy.reason_codes)</code></pre>
    </section>

    <section>
      <h2>Starter YAML Policy</h2>
      <pre><code>id: local_ai_governance_policy
schema_version: "0.2"
default: deny

rules:
  - name: deny_secrets
    effect: deny
    when:
      data.contains_secrets: true

  - name: redact_pii
    effect: transform
    action: redact
    when:
      data.contains_pii: true

  - name: require_approval_for_high_risk
    effect: require_approval
    when:
      risk.tier_in: [high, critical]

  - name: allow_low_medium_risk_developers
    effect: allow
    when:
      user.role_in: [developer, platform_engineer]
      risk.tier_in: [low, medium]</code></pre>
    </section>

    <section>
      <h2>PolicyAware Documentation</h2>
      <ul>
        <li><a href="{self._doc("data")}">Data protection: PII, PHI, secrets, and redaction</a></li>
        <li><a href="{self._doc("policy")}">Policy enforcement and deny-by-default controls</a></li>
        <li><a href="{self._doc("tool")}">MCP and agent tool governance</a></li>
        <li><a href="{self._doc("routing")}">Model routing and provider governance</a></li>
        <li><a href="{self._doc("eval")}">Evaluation, grounding, citations, and leakage checks</a></li>
        <li><a href="{self._doc("audit")}">Audit traces and observability</a></li>
      </ul>
    </section>
  </main>
  <script>
    const textFilter = document.getElementById('filterText');
    const severityFilter = document.getElementById('filterSeverity');
    const categoryFilter = document.getElementById('filterCategory');
    const complianceFilter = document.getElementById('filterCompliance');
    const rows = Array.from(document.querySelectorAll('tr[data-finding-row]'));
    function applyFilters() {{
      const text = textFilter.value.toLowerCase();
      const severity = severityFilter.value;
      const category = categoryFilter.value;
      const compliance = complianceFilter.value;
      for (const row of rows) {{
        const rowText = row.innerText.toLowerCase();
        const severityMatch = !severity || row.dataset.severity === severity;
        const categoryMatch = !category || row.dataset.category === category;
        const complianceMatch = !compliance || row.dataset.compliance === compliance;
        const textMatch = !text || rowText.includes(text);
        row.classList.toggle('hidden-row', !(severityMatch && categoryMatch && complianceMatch && textMatch));
      }}
    }}
    textFilter.addEventListener('input', applyFilters);
    severityFilter.addEventListener('change', applyFilters);
    categoryFilter.addEventListener('change', applyFilters);
    complianceFilter.addEventListener('change', applyFilters);
  </script>
</body>
</html>
"""

    def _doc(self, key: str) -> str:
        return LocalCodeScanner.DOCS[key]


class ScanJsonReportWriter:
    """Render a machine-readable JSON scan report for CI and automation."""

    def write(self, report: ScanReport, out: Path) -> Path:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        return out


class ScanMarkdownReportWriter:
    """Render a compact Markdown report for pull requests and review tickets."""

    def write(self, report: ScanReport, out: Path) -> Path:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.render(report), encoding="utf-8")
        return out

    def render(self, report: ScanReport) -> str:
        lines = [
            "# PolicyAware Local Code Scan Report",
            "",
            f"- Scanned path: `{report.scanned_path}`",
            f"- Generated: `{report.generated_at}`",
            f"- Overall risk: **{report.overall_risk}**",
            f"- Files scanned: `{report.files_scanned}`",
            f"- Files skipped: `{report.files_skipped}`",
            f"- Findings: `{len(report.findings)}`",
            f"- Policy coverage: `{report.policy_coverage_score}%`",
            f"- Suppressed findings: `{report.suppressed_findings}`",
            f"- Baseline ignored: `{report.baseline_ignored}`",
            "",
            "## Severity Counts",
            "",
            "| Severity | Count |",
            "| --- | ---: |",
        ]
        for severity in ("critical", "high", "medium", "low"):
            lines.append(f"| {severity} | {report.severity_counts[severity]} |")
        lines.extend(["", "## Top Recommendations", ""])
        for item in _recommendations_plain(report):
            lines.append(f"- {item}")
        lines.extend(["", "## Findings", ""])
        if not report.findings:
            lines.append("No findings detected.")
            return "\n".join(lines) + "\n"
        lines.extend(
            [
                "| Severity | File | Line | Category | Compliance Area | Finding |",
                "| --- | --- | ---: | --- | --- | --- |",
            ]
        )
        for finding in report.findings:
            lines.append(
                "| "
                f"{finding.severity} | `{finding.file}` | {finding.line} | "
                f"{finding.category} | {finding.compliance_area} | "
                f"{finding.title} |"
            )
        return "\n".join(lines) + "\n"


class ScanSarifReportWriter:
    """Render a SARIF report for GitHub Code Scanning style integrations."""

    def write(self, report: ScanReport, out: Path) -> Path:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(self.render(report), indent=2), encoding="utf-8")
        return out

    def render(self, report: ScanReport) -> dict[str, object]:
        rules: dict[str, dict[str, object]] = {}
        results: list[dict[str, object]] = []
        for finding in report.findings:
            rule_id = _sarif_rule_id(finding.category)
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": finding.category,
                    "shortDescription": {"text": finding.category},
                    "helpUri": finding.docs_url,
                },
            )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": _sarif_level(finding.severity),
                    "message": {
                        "text": f"{finding.title}. {finding.recommendation}",
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.file.replace("\\", "/")},
                                "region": {"startLine": max(finding.line, 1)},
                            }
                        }
                    ],
                    "properties": {
                        "severity": finding.severity,
                        "category": finding.category,
                        "compliance_area": finding.compliance_area,
                        "evidence": finding.evidence,
                        "fix_snippet": finding.fix_snippet,
                    },
                }
            )
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PolicyAware Local Code Scan",
                            "informationUri": "https://github.com/ktirupati/policyaware",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "properties": {
                        "scanned_path": report.scanned_path,
                        "generated_at": report.generated_at,
                        "overall_risk": report.overall_risk,
                        "files_scanned": report.files_scanned,
                    },
                }
            ],
        }


def _finding_row(finding: ScanFinding) -> str:
    return f"""
<tr data-finding-row data-severity="{html.escape(finding.severity)}" data-category="{html.escape(finding.category)}" data-compliance="{html.escape(finding.compliance_area)}">
  <td><span class="sev sev-{html.escape(finding.severity)}">{html.escape(finding.severity)}</span></td>
  <td><code>{html.escape(finding.file)}</code></td>
  <td>{finding.line}</td>
  <td>{html.escape(finding.category)}</td>
  <td>{html.escape(finding.compliance_area)}</td>
  <td><strong>{html.escape(finding.title)}</strong><br><span class="muted">{html.escape(finding.evidence)}</span><br><span class="muted">Fingerprint: <code>{html.escape(finding.fingerprint)}</code></span></td>
  <td>{html.escape(finding.recommendation)}<br>{_fix_html(finding)}<br><a href="{html.escape(finding.docs_url)}">PolicyAware docs</a></td>
</tr>"""


def _file_section(file: str, findings: list[ScanFinding]) -> str:
    items = "\n".join(
        f"""<details>
  <summary><span class="sev sev-{html.escape(finding.severity)}">{html.escape(finding.severity)}</span>
  line {finding.line}: {html.escape(finding.title)}</summary>
  <p><strong>Category:</strong> {html.escape(finding.category)}</p>
  <p><strong>Evidence:</strong> <code>{html.escape(finding.evidence)}</code></p>
  <p><strong>Fingerprint:</strong> <code>{html.escape(finding.fingerprint)}</code></p>
  <p><strong>Compliance Area:</strong> {html.escape(finding.compliance_area)}</p>
  <p><strong>Recommendation:</strong> {html.escape(finding.recommendation)}</p>
  {_fix_html(finding)}
  <p><a href="{html.escape(finding.docs_url)}">Read the related PolicyAware documentation</a></p>
</details>"""
        for finding in findings
    )
    return f"<h3><code>{html.escape(file)}</code></h3>{items}"


def _recommendations(report: ScanReport) -> str:
    return "\n".join(f"<li>{html.escape(item)}</li>" for item in _recommendations_plain(report))


def _recommendations_plain(report: ScanReport) -> list[str]:
    categories = report.category_counts
    recommendations: list[str] = []
    if categories["Secrets"]:
        recommendations.append(
            "Rotate exposed credentials, move secrets to environment variables or a secret manager, and enable PolicyAware secret checks before model calls."
        )
    if categories["PII"] or categories["PHI"]:
        recommendations.append(
            "Redact or tokenize sensitive data before sending prompts to models, tools, logs, or evaluation reports."
        )
    if categories["LLM Governance"]:
        recommendations.append(
            "Wrap direct LLM calls with PolicyAware Gateway so every prompt receives policy, risk, routing, and audit checks."
        )
    if categories["Tool Governance"]:
        recommendations.append(
            "Define connector-level and action-level policies for agent tools, with approval required for write, delete, deploy, refund, or payment actions."
        )
    if categories["Agent Tool Governance"]:
        recommendations.append(
            "Govern MCP, function-calling, and agent tool registrations with explicit allow, deny, and approval policies."
        )
    if categories["Prompt Safety"]:
        recommendations.append(
            "Review prompt templates for instruction-bypass language and add prompt-injection checks before model or tool execution."
        )
    if categories["RAG Governance"]:
        recommendations.append(
            "Add grounding and citation evaluations for RAG answers, especially for regulated or factual workflows."
        )
    if categories["Policy YAML"]:
        recommendations.append(
            "Validate YAML policies and keep deny-by-default behavior so unrecognized requests fail closed."
        )
    if categories["Auditability"]:
        recommendations.append(
            "Record audit traces with request, policy decision, route, evaluation result, and response metadata."
        )
    if categories["Data Pipeline Governance"]:
        recommendations.append(
            "Add sensitive-column classification, masking, and audit metadata before Spark or pipeline writes."
        )
    if categories["Provider Governance"]:
        recommendations.append(
            "Centralize model providers in PolicyAware routing so provider choice follows risk, role, region, cost, and compliance policy."
        )
    if categories["Data Residency"]:
        recommendations.append(
            "Add region, tenant, and approved-provider constraints before regulated data reaches external endpoints."
        )
    if categories["Autonomous Agent Governance"]:
        recommendations.append(
            "Add human approval, maximum iterations, budget limits, and audit traces before autonomous agent execution."
        )
    if categories["Cost Governance"]:
        recommendations.append(
            "Define token, latency, rate, retry, and cost limits for model and agent workflows."
        )
    if categories["Configuration Governance"]:
        recommendations.append(
            "Review Docker, Kubernetes, Terraform, CI/CD, and env-style files for plaintext secrets and unsafe configuration defaults."
        )
    if not recommendations:
        recommendations.append(
            "No high-signal findings were detected. Keep PolicyAware scanning in local development and CI to catch regressions."
        )
    return recommendations


def _remediation_checklist(report: ScanReport) -> str:
    if not report.findings:
        items = [
            "Keep `policyaware scan` in local development and CI.",
            "Review policies when adding new providers, tools, RAG flows, or autonomous agents.",
        ]
        return "\n".join(f"<li>{html.escape(item)}</li>" for item in items)

    checklist = [
        "Fix or rotate critical secrets before sharing or deploying this code.",
        "Route direct model calls through PolicyAware Gateway.",
        "Add connector/action permissions and approval requirements for risky tools.",
        "Add region, tenant, provider, budget, and latency controls for model and agent workflows.",
        "Add RAG citation, grounding, and sensitive-data leakage evaluations.",
        "Record audit traces for request, decision, route, tool call, evaluation, and response metadata.",
        "Re-run `policyaware scan` and commit only after high-risk findings are resolved or explicitly suppressed.",
    ]
    categories = report.category_counts
    if not categories["Secrets"]:
        checklist.remove("Fix or rotate critical secrets before sharing or deploying this code.")
    if not categories["LLM Governance"]:
        checklist.remove("Route direct model calls through PolicyAware Gateway.")
    if not (categories["Tool Governance"] or categories["Agent Tool Governance"]):
        checklist.remove("Add connector/action permissions and approval requirements for risky tools.")
    if not (categories["Provider Governance"] or categories["Data Residency"] or categories["Cost Governance"]):
        checklist.remove("Add region, tenant, provider, budget, and latency controls for model and agent workflows.")
    if not categories["RAG Governance"]:
        checklist.remove("Add RAG citation, grounding, and sensitive-data leakage evaluations.")
    if not categories["Auditability"]:
        checklist.remove("Record audit traces for request, decision, route, tool call, evaluation, and response metadata.")
    return "\n".join(f"<li>{html.escape(item)}</li>" for item in checklist)


def _category_options(categories: Counter[str]) -> str:
    return "\n".join(
        f'<option value="{html.escape(category)}">{html.escape(category)}</option>'
        for category in sorted(categories)
    )


def _coverage_text(report: ScanReport) -> str:
    if not report.policy_coverage_missing:
        return "No major policy coverage gaps were inferred from this scan."
    missing = ", ".join(html.escape(item) for item in report.policy_coverage_missing)
    return f"Coverage score is {report.policy_coverage_score}%. Missing or weak areas: {missing}."


def _reviewer_summary(report: ScanReport) -> str:
    if not report.findings:
        return "Governance posture is clean for the current fast scan. Keep scanning in local development and CI."
    top = report.category_counts.most_common(4)
    top_text = ", ".join(f"{category} ({count})" for category, count in top)
    return (
        f"Governance posture: {report.overall_risk}. Main review areas: {top_text}. "
        "Fix critical secrets first, then address direct model/tool execution, data handling, "
        "approval, region, budget, RAG grounding, and audit coverage gaps."
    )


def _compliance_chips(report: ScanReport) -> str:
    if not report.findings:
        return "<span class='chip'>No compliance gaps inferred</span>"
    return "\n".join(
        f"<span class='chip'>{html.escape(area)} <strong>{count}</strong></span>"
        for area, count in report.compliance_counts.most_common()
    )


def _fix_html(finding: ScanFinding) -> str:
    if not finding.fix_snippet:
        return ""
    return f"<details><summary>Suggested fix</summary><pre><code>{html.escape(finding.fix_snippet)}</code></pre></details>"


def git_changed_files(root: Path, base_ref: str = "HEAD") -> list[str]:
    """Return changed files relative to a Git ref, using paths relative to root."""

    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "diff", "--name-only", base_ref],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []
    return [line.strip().replace("\\", "/") for line in completed.stdout.splitlines() if line.strip()]


def _read_scan_text(path: Path) -> str:
    if path.suffix.lower() == ".ipynb":
        return _read_notebook_text(path)
    return path.read_text(encoding="utf-8", errors="ignore")


def _read_notebook_text(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")
    chunks: list[str] = []
    for cell in payload.get("cells", []):
        source = cell.get("source", [])
        if isinstance(source, list):
            chunks.extend(str(line) for line in source)
        elif isinstance(source, str):
            chunks.append(source)
        chunks.append("\n")
    return "".join(chunks)


def _has_file_suppression(text: str) -> bool:
    return bool(re.search(r"policyaware-ignore-file", text, re.I))


def _has_policyaware_gateway(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or _looks_like_comment_only(stripped):
            continue
        lowered = stripped.lower()
        if (
            "import policyaware" in lowered
            or "from policyaware" in lowered
            or "gateway.from_policy_file" in lowered
            or "policyaware.gateway" in lowered
        ):
            return True
    return False


def _suppressed_lines(text: str) -> set[int]:
    suppressed: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        if "policyaware-ignore-line" in lowered:
            suppressed.add(line_number)
        if "policyaware-ignore-next-line" in lowered:
            suppressed.add(line_number + 1)
    return suppressed


def _optional_frozenset(value: object) -> frozenset[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return frozenset({value})
    try:
        return frozenset(str(item) for item in value)  # type: ignore[arg-type]
    except TypeError:
        return None


def _parse_config_size(value: object) -> int | None:
    if value in {None, ""}:
        return None
    normalized = str(value).strip().lower()
    multiplier = 1
    if normalized.endswith("kb"):
        multiplier = 1024
        normalized = normalized[:-2]
    elif normalized.endswith("mb"):
        multiplier = 1024 * 1024
        normalized = normalized[:-2]
    elif normalized.endswith("b"):
        normalized = normalized[:-1]
    try:
        return int(float(normalized) * multiplier)
    except ValueError:
        return None


def _governance_posture(report: ScanReport) -> dict[str, object]:
    blockers = report.severity_counts["critical"] + report.severity_counts["high"]
    if report.overall_risk in {"Critical", "High"}:
        readiness = "Needs remediation before production release"
    elif report.overall_risk == "Medium":
        readiness = "Usable for development with governance follow-up"
    elif report.overall_risk == "Low":
        readiness = "Low-risk posture for the scanned files"
    else:
        readiness = "No findings detected by the fast local scan"
    return {
        "readiness": readiness,
        "release_blockers": blockers,
        "policy_coverage_score": report.policy_coverage_score,
        "policy_coverage_missing": report.policy_coverage_missing,
        "top_categories": [
            {"category": category, "count": count}
            for category, count in report.category_counts.most_common(5)
        ],
        "top_compliance_areas": [
            {"area": area, "count": count}
            for area, count in report.compliance_counts.most_common(5)
        ],
    }


def _compliance_framework_mapping(report: ScanReport) -> dict[str, list[str]]:
    mapping = {
        "HIPAA": {"PHI", "Data Residency", "Auditability", "Data Pipeline Governance"},
        "GDPR": {"PII", "Data Residency", "Auditability"},
        "SOC 2": {"Secrets", "Auditability", "Tool Governance", "Configuration Governance"},
        "ISO 27001": {"Secrets", "Configuration Governance", "Auditability", "Provider Governance"},
        "PCI DSS": {"Secrets", "PII", "Data Pipeline Governance"},
        "AI Governance": {
            "LLM Governance",
            "Provider Governance",
            "Tool Governance",
            "Agent Tool Governance",
            "Autonomous Agent Governance",
            "RAG Governance",
            "Prompt Safety",
            "Cost Governance",
        },
    }
    categories = set(report.category_counts)
    return {
        framework: sorted(categories & framework_categories)
        for framework, framework_categories in mapping.items()
        if categories & framework_categories
    }


def _compliance_area(category: str) -> str:
    return {
        "Secrets": "Security / Secrets Management",
        "PII": "Privacy / Data Protection",
        "PHI": "Regulated Data / Healthcare Privacy",
        "LLM Governance": "Model Governance",
        "Provider Governance": "Provider Governance",
        "Data Residency": "Region / Data Residency",
        "Tool Governance": "Human Oversight / Tool Governance",
        "Agent Tool Governance": "Agent Tool Governance",
        "Autonomous Agent Governance": "Human Oversight",
        "Cost Governance": "Cost / Usage Governance",
        "RAG Governance": "Grounding / RAG Governance",
        "Auditability": "Auditability",
        "Policy YAML": "Policy Governance",
        "Data Pipeline Governance": "Data Pipeline Governance",
        "Configuration Governance": "Secure Configuration",
        "Prompt Safety": "Prompt Safety",
    }.get(category, "Governance")


def _fix_snippet(category: str) -> str:
    snippets = {
        "Secrets": """# Move secrets out of source code.
import os

api_key = os.environ["OPENAI_API_KEY"]""",
        "PII": """from policyaware import DataProtectionEngine

engine = DataProtectionEngine()
safe_prompt = engine.redact(user_prompt).redacted_text""",
        "PHI": """from policyaware import Gateway, GatewayRequest

gateway = Gateway.from_policy_file("examples/policies/healthcare.yaml")
# Regulated requests should use PHI redaction and approved routes.""",
        "LLM Governance": """from policyaware import Gateway, GatewayRequest

gateway = Gateway.from_policy_file("policyaware.yaml")
response = gateway.chat(GatewayRequest(
    tenant="acme",
    app="assistant",
    user={"id": user_id, "role": "developer"},
    context={"risk": "medium", "region": "us"},
    messages=[{"role": "user", "content": prompt}],
))""",
        "Provider Governance": """routing:
  strategy: policy_aware
  providers:
    - name: internal-local
      type: local
      allowed_for: [sensitive, regulated, high]
    - name: external-approved
      type: external
      allowed_for: [public, low, medium]""",
        "Data Residency": """rules:
  - name: regulated_data_requires_approved_region
    effect: deny
    when:
      data.contains_phi: true
      context.region_not_in: [us-east, us-west]""",
        "Tool Governance": """tool_policies:
  - connector: github
    action: delete_repo
    effect: require_approval
    allowed_roles: [platform_admin]""",
        "Agent Tool Governance": """tool_policies:
  - connector: "*"
    action: "*"
    effect: deny
  - connector: jira
    action: create_ticket
    effect: allow
    allowed_roles: [engineer, support]""",
        "Autonomous Agent Governance": """agent_controls:
  max_iterations: 5
  require_approval_for: [write, delete, deploy, payment]
  audit_each_tool_call: true""",
        "Cost Governance": """limits:
  max_tokens_per_request: 4000
  max_cost_usd_per_request: 0.25
  timeout_seconds: 30
  max_tool_calls: 10""",
        "RAG Governance": """eval:
  require_citations: true
  require_grounding: true
  min_groundedness_score: 0.80""",
        "Auditability": """audit:
  enabled: true
  capture: [request, policy_decision, route, evaluation, response_metadata]""",
        "Policy YAML": """id: local_ai_governance_policy
schema_version: "0.2"
default: deny
rules: []""",
        "Data Pipeline Governance": """# Before writing data, classify and mask sensitive columns.
safe_df = mask_sensitive_columns(df, columns=["email", "phone", "patient_id"])
safe_df.write.saveAsTable("governed.output")""",
        "Configuration Governance": """# Store real secrets outside config files.
env:
  OPENAI_API_KEY:
    from_secret_manager: policyaware/openai-api-key""",
        "Prompt Safety": """rules:
  - name: block_prompt_injection_language
    effect: deny
    when:
      prompt.contains_injection_pattern: true""",
    }
    return snippets.get(category, "")


def _with_fingerprint(finding: ScanFinding) -> ScanFinding:
    if finding.fingerprint:
        if finding.compliance_area and finding.fix_snippet:
            return finding
        return replace(
            finding,
            compliance_area=finding.compliance_area or _compliance_area(finding.category),
            fix_snippet=finding.fix_snippet or _fix_snippet(finding.category),
        )
    raw = "|".join(
        [
            finding.category,
            finding.severity,
            finding.file.replace("\\", "/"),
            str(finding.line),
            finding.title,
            finding.evidence,
        ]
    )
    digest = sha256(raw.encode("utf-8")).hexdigest()[:16]
    return replace(
        finding,
        fingerprint=f"policyaware:{digest}",
        compliance_area=finding.compliance_area or _compliance_area(finding.category),
        fix_snippet=finding.fix_snippet or _fix_snippet(finding.category),
    )


def _policy_coverage(findings: list[ScanFinding]) -> tuple[int, list[str]]:
    gap_by_category = {
        "Secrets": "secret handling",
        "PII": "PII redaction",
        "PHI": "regulated-data handling",
        "LLM Governance": "gateway enforcement before model calls",
        "Prompt Safety": "prompt safety checks",
        "Tool Governance": "tool approval policy",
        "Agent Tool Governance": "agent/MCP tool permissions",
        "RAG Governance": "RAG citation and grounding evaluation",
        "Auditability": "audit trace capture",
        "Policy YAML": "valid deny-by-default policy",
        "Data Pipeline Governance": "data pipeline masking and audit controls",
        "Provider Governance": "approved-provider routing",
        "Data Residency": "region and endpoint controls",
        "Autonomous Agent Governance": "human oversight for autonomous agents",
        "Cost Governance": "cost and rate limits",
        "Configuration Governance": "secure configuration management",
    }
    missing = sorted({gap_by_category[finding.category] for finding in findings if finding.category in gap_by_category})
    total_controls = len(set(gap_by_category.values()))
    score = max(0, round(((total_controls - len(missing)) / total_controls) * 100))
    return score, missing


def _redact_evidence(text: str) -> str:
    redacted = DataProtectionEngine().redact(text).redacted_text or text
    redacted = re.sub(
        r"""(?ix)
        (api[_-]?key|secret|token|password|access[_-]?key|private[_-]?key)
        (\s*[:=]\s*)['"]?([A-Za-z0-9_./+=\-]{6,})['"]?
        """,
        r"\1\2[REDACTED_SECRET]",
        redacted,
    )
    return redacted[:240]


def _looks_like_comment_only(line: str) -> bool:
    return line.startswith(("#", "//", "/*", "*", "<!--"))


def _is_code_file(path: Path) -> bool:
    return path.suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx"}


def _is_config_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    name = path.name.lower()
    if name.startswith(".env"):
        return True
    return suffix in {
        ".env",
        ".yml",
        ".yaml",
        ".json",
        ".toml",
        ".ini",
        ".properties",
        ".tf",
        ".hcl",
        ".dockerfile",
    } or name in {
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    }


def _first_match_line(text: str, pattern: re.Pattern[str]) -> int:
    for index, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return index
    return 1


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(severity, 9)


def _risk_color(risk: str) -> str:
    return {
        "Critical": "var(--critical)",
        "High": "var(--high)",
        "Medium": "var(--medium)",
        "Low": "var(--low)",
        "Clean": "var(--clean)",
    }.get(risk, "var(--text)")


def _sarif_rule_id(category: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", category.lower()).strip("-")
    return f"policyaware-{normalized or 'finding'}"


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
