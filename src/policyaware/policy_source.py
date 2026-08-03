from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import yaml

from policyaware.models import DataFindings, Decision, GatewayRequest, PolicyDecision, RiskAssessment
from policyaware.policy import PolicyEngine


@dataclass(frozen=True)
class PolicySourceSnapshot:
    source: str
    version: str
    loaded_at: float
    policy: dict[str, Any]
    sha256: str


class PolicySourceError(RuntimeError):
    pass


class PolicySource:
    def load(self) -> PolicySourceSnapshot:
        raise NotImplementedError


class FilePolicySource(PolicySource):
    def __init__(self, path: str | Path, *, expected_sha256: str | None = None):
        self.path = Path(path)
        self.expected_sha256 = expected_sha256

    def load(self) -> PolicySourceSnapshot:
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicySourceError(f"Could not read policy file: {self.path}") from exc
        return _snapshot(str(self.path.resolve()), text, expected_sha256=self.expected_sha256)


class HttpPolicySource(PolicySource):
    def __init__(
        self,
        url: str,
        *,
        auth_token: str | None = None,
        timeout_seconds: float = 5.0,
        cache_file: str | Path | None = None,
        expected_sha256: str | None = None,
    ):
        self.url = url
        self.auth_token = auth_token
        self.timeout_seconds = timeout_seconds
        self.cache_file = Path(cache_file) if cache_file else None
        self.expected_sha256 = expected_sha256

    def load(self) -> PolicySourceSnapshot:
        request = Request(self.url, headers=self._headers())
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:  # noqa: S310 - explicit user URL
                text = response.read().decode("utf-8")
            if self.cache_file:
                self.cache_file.parent.mkdir(parents=True, exist_ok=True)
                self.cache_file.write_text(text, encoding="utf-8")
            return _snapshot(self.url, text, expected_sha256=self.expected_sha256)
        except (OSError, URLError) as exc:
            if self.cache_file and self.cache_file.exists():
                text = self.cache_file.read_text(encoding="utf-8")
                return _snapshot(
                    f"{self.url} cached:{self.cache_file}",
                    text,
                    expected_sha256=self.expected_sha256,
                )
            raise PolicySourceError(f"Could not fetch policy source: {self.url}") from exc

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/x-yaml, application/yaml, text/yaml, text/plain"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers


class AzureDataLakePolicySource(PolicySource):
    """Load policy YAML from ADLS Gen2 abfs:// or abfss:// paths."""

    def __init__(
        self,
        uri: str,
        *,
        auth_token: str | None = None,
        cache_file: str | Path | None = None,
        expected_sha256: str | None = None,
    ):
        self.uri = uri
        self.auth_token = auth_token
        self.cache_file = Path(cache_file) if cache_file else None
        self.expected_sha256 = expected_sha256
        parsed = parse_adls_uri(uri)
        self.account_url = parsed["account_url"]
        self.file_system = parsed["file_system"]
        self.file_path = parsed["file_path"]

    def load(self) -> PolicySourceSnapshot:
        try:
            text = self._download_text()
            if self.cache_file:
                self.cache_file.parent.mkdir(parents=True, exist_ok=True)
                self.cache_file.write_text(text, encoding="utf-8")
            return _snapshot(self.uri, text, expected_sha256=self.expected_sha256)
        except Exception as exc:
            if self.cache_file and self.cache_file.exists():
                text = self.cache_file.read_text(encoding="utf-8")
                return _snapshot(
                    f"{self.uri} cached:{self.cache_file}",
                    text,
                    expected_sha256=self.expected_sha256,
                )
            raise PolicySourceError(f"Could not fetch ADLS Gen2 policy source: {self.uri}") from exc

    def _download_text(self) -> str:
        try:
            from azure.core.credentials import AzureSasCredential
            from azure.identity import DefaultAzureCredential
            from azure.storage.filedatalake import DataLakeFileClient
        except ImportError as exc:
            raise PolicySourceError(
                "ADLS Gen2 policy sources require: pip install 'policyaware[azure]'"
            ) from exc

        credential = AzureSasCredential(self.auth_token) if self.auth_token else DefaultAzureCredential()
        client = DataLakeFileClient(
            account_url=self.account_url,
            file_system_name=self.file_system,
            file_path=self.file_path,
            credential=credential,
        )
        data = client.download_file().readall()
        if isinstance(data, bytes):
            return data.decode("utf-8")
        return str(data)


class S3PolicySource(PolicySource):
    """Load policy YAML from AWS S3 s3://bucket/key paths."""

    def __init__(
        self,
        uri: str,
        *,
        cache_file: str | Path | None = None,
        expected_sha256: str | None = None,
    ):
        self.uri = uri
        self.cache_file = Path(cache_file) if cache_file else None
        self.expected_sha256 = expected_sha256
        parsed = parse_s3_uri(uri)
        self.bucket = parsed["bucket"]
        self.key = parsed["key"]

    def load(self) -> PolicySourceSnapshot:
        try:
            text = self._download_text()
            if self.cache_file:
                self.cache_file.parent.mkdir(parents=True, exist_ok=True)
                self.cache_file.write_text(text, encoding="utf-8")
            return _snapshot(self.uri, text, expected_sha256=self.expected_sha256)
        except Exception as exc:
            if self.cache_file and self.cache_file.exists():
                text = self.cache_file.read_text(encoding="utf-8")
                return _snapshot(
                    f"{self.uri} cached:{self.cache_file}",
                    text,
                    expected_sha256=self.expected_sha256,
                )
            raise PolicySourceError(f"Could not fetch S3 policy source: {self.uri}") from exc

    def _download_text(self) -> str:
        try:
            import boto3
        except ImportError as exc:
            raise PolicySourceError("S3 policy sources require: pip install 'policyaware[providers]'") from exc
        response = boto3.client("s3").get_object(Bucket=self.bucket, Key=self.key)
        return response["Body"].read().decode("utf-8")


class GoogleCloudStoragePolicySource(PolicySource):
    """Load policy YAML from Google Cloud Storage gs://bucket/blob paths."""

    def __init__(
        self,
        uri: str,
        *,
        cache_file: str | Path | None = None,
        expected_sha256: str | None = None,
    ):
        self.uri = uri
        self.cache_file = Path(cache_file) if cache_file else None
        self.expected_sha256 = expected_sha256
        parsed = parse_gcs_uri(uri)
        self.bucket = parsed["bucket"]
        self.blob = parsed["blob"]

    def load(self) -> PolicySourceSnapshot:
        try:
            text = self._download_text()
            if self.cache_file:
                self.cache_file.parent.mkdir(parents=True, exist_ok=True)
                self.cache_file.write_text(text, encoding="utf-8")
            return _snapshot(self.uri, text, expected_sha256=self.expected_sha256)
        except Exception as exc:
            if self.cache_file and self.cache_file.exists():
                text = self.cache_file.read_text(encoding="utf-8")
                return _snapshot(
                    f"{self.uri} cached:{self.cache_file}",
                    text,
                    expected_sha256=self.expected_sha256,
                )
            raise PolicySourceError(f"Could not fetch GCS policy source: {self.uri}") from exc

    def _download_text(self) -> str:
        try:
            from google.cloud import storage
        except ImportError as exc:
            raise PolicySourceError("GCS policy sources require: pip install 'policyaware[gcp]'") from exc
        client = storage.Client()
        return client.bucket(self.bucket).blob(self.blob).download_as_text(encoding="utf-8")


class DynamicPolicyEngine:
    """Policy engine wrapper that refreshes policy from a source on a TTL."""

    def __init__(
        self,
        source: PolicySource,
        *,
        refresh_seconds: float = 60.0,
        fail_closed: bool = True,
    ):
        self.source = source
        self.refresh_seconds = refresh_seconds
        self.fail_closed = fail_closed
        self.snapshot: PolicySourceSnapshot | None = None
        self._engine: PolicyEngine | None = None
        self._last_attempt = 0.0
        self.refresh(force=True)

    @property
    def policy(self) -> dict[str, Any]:
        return self._engine.policy if self._engine else {"default": "deny", "rules": []}

    def refresh(self, *, force: bool = False) -> bool:
        now = time.time()
        if not force and now - self._last_attempt < self.refresh_seconds:
            return False
        self._last_attempt = now
        try:
            snapshot = self.source.load()
            engine = PolicyEngine(snapshot.policy)
        except Exception:
            if self.fail_closed or self._engine is None:
                raise
            return False
        self.snapshot = snapshot
        self._engine = engine
        return True

    def decide(
        self,
        request: GatewayRequest,
        findings: DataFindings,
        risk: RiskAssessment | None = None,
    ) -> PolicyDecision:
        try:
            self.refresh()
        except Exception:
            if self.fail_closed:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason="Denied because dynamic policy source could not be refreshed.",
                    reason_codes=["POLICY.SOURCE_UNAVAILABLE"],
                    remediation=["Restore policy distribution or provide a valid cached policy."],
                )
        if self._engine is None:
            return PolicyDecision(
                decision=Decision.DENY,
                reason="Denied because no dynamic policy engine is loaded.",
                reason_codes=["POLICY.SOURCE_UNAVAILABLE"],
                remediation=["Configure a reachable policy source."],
            )
        return self._engine.decide(request, findings, risk)


def policy_source_from_uri(
    source: str | Path,
    *,
    auth_token: str | None = None,
    cache_file: str | Path | None = None,
    timeout_seconds: float = 5.0,
    expected_sha256: str | None = None,
) -> PolicySource:
    source_text = str(source)
    if is_url(source_text):
        return HttpPolicySource(
            source_text,
            auth_token=auth_token,
            cache_file=cache_file,
            timeout_seconds=timeout_seconds,
            expected_sha256=expected_sha256,
        )
    if is_adls_uri(source_text):
        return AzureDataLakePolicySource(
            source_text,
            auth_token=auth_token,
            cache_file=cache_file,
            expected_sha256=expected_sha256,
        )
    if is_s3_uri(source_text):
        return S3PolicySource(source_text, cache_file=cache_file, expected_sha256=expected_sha256)
    if is_gcs_uri(source_text):
        return GoogleCloudStoragePolicySource(
            source_text,
            cache_file=cache_file,
            expected_sha256=expected_sha256,
        )
    return FilePolicySource(source_text, expected_sha256=expected_sha256)


def is_url(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def is_adls_uri(value: str) -> bool:
    return value.startswith(("abfs://", "abfss://"))


def is_s3_uri(value: str) -> bool:
    return value.startswith("s3://")


def is_gcs_uri(value: str) -> bool:
    return value.startswith("gs://")


def parse_adls_uri(uri: str) -> dict[str, str]:
    parsed = urlparse(uri)
    if parsed.scheme not in {"abfs", "abfss"}:
        raise PolicySourceError("ADLS Gen2 policy source must use abfs:// or abfss://.")
    if "@" not in parsed.netloc:
        raise PolicySourceError(
            "ADLS Gen2 URI must look like abfss://container@account.dfs.core.windows.net/path.yaml."
        )
    file_system, host = parsed.netloc.split("@", 1)
    file_path = parsed.path.lstrip("/")
    if not file_system or not host or not file_path:
        raise PolicySourceError(
            "ADLS Gen2 URI must include a container, account host, and policy file path."
        )
    return {
        "account_url": f"https://{host}",
        "file_system": file_system,
        "file_path": file_path,
    }


def parse_s3_uri(uri: str) -> dict[str, str]:
    parsed = urlparse(uri)
    if parsed.scheme != "s3":
        raise PolicySourceError("S3 policy source must use s3://.")
    bucket = parsed.netloc
    key = parsed.path.lstrip("/")
    if not bucket or not key:
        raise PolicySourceError("S3 URI must look like s3://bucket/path/policyaware.yaml.")
    return {"bucket": bucket, "key": key}


def parse_gcs_uri(uri: str) -> dict[str, str]:
    parsed = urlparse(uri)
    if parsed.scheme != "gs":
        raise PolicySourceError("GCS policy source must use gs://.")
    bucket = parsed.netloc
    blob = parsed.path.lstrip("/")
    if not bucket or not blob:
        raise PolicySourceError("GCS URI must look like gs://bucket/path/policyaware.yaml.")
    return {"bucket": bucket, "blob": blob}


def _snapshot(source: str, text: str, *, expected_sha256: str | None = None) -> PolicySourceSnapshot:
    digest = _sha256(text)
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        raise PolicySourceError(
            f"Policy checksum mismatch for {source}: expected {expected_sha256}, got {digest}."
        )
    policy = yaml.safe_load(text) or {}
    if not isinstance(policy, dict):
        raise PolicySourceError("Policy source must contain a YAML mapping/object.")
    version = str(policy.get("version") or policy.get("schema_version") or _sha256(text)[:12])
    return PolicySourceSnapshot(
        source=source,
        version=version,
        loaded_at=time.time(),
        policy=policy,
        sha256=digest,
    )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
