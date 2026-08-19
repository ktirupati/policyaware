from __future__ import annotations

import gc
import hashlib
import logging
import time
import weakref
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock

import pytest
from typer.testing import CliRunner

from policyaware import (
    AzureDataLakePolicySource,
    DataFindings,
    DynamicPolicyEngine,
    FallbackPolicySource,
    FilePolicySource,
    Gateway,
    GatewayRequest,
    GoogleCloudStoragePolicySource,
    HttpPolicySource,
    S3PolicySource,
    parse_adls_uri,
    parse_gcs_uri,
    parse_s3_uri,
)
from policyaware.cli import app
from policyaware.policy_source import (
    PolicySource,
    PolicySourceError,
    PolicySourceSnapshot,
    policy_source_from_uri,
)


ALLOW_POLICY = """
default: deny
rules:
  - name: allow_support
    effect: allow
    when:
      user.role: support_agent
"""


DENY_POLICY = """
default: deny
rules:
  - name: emergency_revoke_support
    effect: deny
    when:
      user.role: support_agent
"""


def test_gateway_refreshes_dynamic_file_policy(tmp_path: Path) -> None:
    policy = tmp_path / "policyaware.yaml"
    policy.write_text(ALLOW_POLICY, encoding="utf-8")
    gateway = Gateway.from_policy_source(policy, refresh_seconds=0)
    request = GatewayRequest(
        tenant="acme",
        app="dynamic-policy-test",
        user={"role": "support_agent"},
        context={"region": "us", "risk": "low", "task_type": "support"},
        messages=[{"role": "user", "content": "Summarize this ticket."}],
    )

    allowed = gateway.chat(request)
    policy.write_text(DENY_POLICY, encoding="utf-8")
    denied = gateway.chat(request)

    assert allowed.policy.decision.value in {"allow", "conditional_allow"}
    assert denied.policy.decision.value == "deny"
    assert denied.policy.matched_rules == ["emergency_revoke_support"]


def test_policy_pull_cli_validates_and_writes_policy(tmp_path: Path) -> None:
    source = tmp_path / "central-policy.yaml"
    out = tmp_path / "policyaware.yaml"
    source.write_text(ALLOW_POLICY, encoding="utf-8")

    result = CliRunner().invoke(app, ["policy", "pull", str(source), "--out", str(out)])

    assert result.exit_code == 0
    assert out.exists()
    assert "allow_support" in out.read_text(encoding="utf-8")


def test_adls_gen2_uri_parsing() -> None:
    parsed = parse_adls_uri(
        "abfss://policy-configs@acmeai.dfs.core.windows.net/prod/policyaware.yaml"
    )

    assert parsed == {
        "account_url": "https://acmeai.dfs.core.windows.net",
        "file_system": "policy-configs",
        "file_path": "prod/policyaware.yaml",
    }


def test_policy_source_from_uri_supports_adls_gen2() -> None:
    source = policy_source_from_uri(
        "abfss://policy-configs@acmeai.dfs.core.windows.net/prod/policyaware.yaml",
        cache_file=".policyaware/policy-cache.yaml",
        timeout_seconds=3.0,
    )

    assert isinstance(source, AzureDataLakePolicySource)
    assert source.file_system == "policy-configs"
    assert source.file_path == "prod/policyaware.yaml"
    assert source.timeout_seconds == 3.0


def test_s3_uri_parsing_and_source_selection() -> None:
    parsed = parse_s3_uri("s3://policy-configs/prod/policyaware.yaml")
    source = policy_source_from_uri("s3://policy-configs/prod/policyaware.yaml", timeout_seconds=4.0)

    assert parsed == {"bucket": "policy-configs", "key": "prod/policyaware.yaml"}
    assert isinstance(source, S3PolicySource)
    assert source.bucket == "policy-configs"
    assert source.key == "prod/policyaware.yaml"
    assert source.timeout_seconds == 4.0


def test_gcs_uri_parsing_and_source_selection() -> None:
    parsed = parse_gcs_uri("gs://policy-configs/prod/policyaware.yaml")
    source = policy_source_from_uri("gs://policy-configs/prod/policyaware.yaml", timeout_seconds=2.5)

    assert parsed == {"bucket": "policy-configs", "blob": "prod/policyaware.yaml"}
    assert isinstance(source, GoogleCloudStoragePolicySource)
    assert source.bucket == "policy-configs"
    assert source.blob == "prod/policyaware.yaml"
    assert source.timeout_seconds == 2.5


def test_http_policy_source_selection_propagates_timeout() -> None:
    source = policy_source_from_uri("https://policy.example.com/policyaware.yaml", timeout_seconds=3.5)

    assert isinstance(source, HttpPolicySource)
    assert source.timeout_seconds == 3.5


def test_fallback_policy_source_loads_restrictive_policy_when_primary_unavailable(tmp_path: Path) -> None:
    fallback = tmp_path / "emergency-fallback.yaml"
    fallback.write_text(DENY_POLICY, encoding="utf-8")
    engine = DynamicPolicyEngine(
        FallbackPolicySource(FailingPolicySource(), FilePolicySource(fallback)),
        refresh_seconds=0,
        fail_closed=True,
    )
    request = GatewayRequest(
        tenant="acme",
        app="fallback-test",
        user={"role": "support_agent"},
        context={"region": "us", "risk": "low", "task_type": "support"},
        messages=[{"role": "user", "content": "Summarize this ticket."}],
    )

    decision = engine.decide(request, findings=DataFindings())

    assert engine.snapshot is not None
    assert "fallback_after" in engine.snapshot.source
    assert decision.decision.value == "deny"
    assert decision.matched_rules == ["emergency_revoke_support"]


def test_remote_policy_cache_wins_before_fallback(tmp_path: Path) -> None:
    cache = tmp_path / "policy-cache.yaml"
    fallback = tmp_path / "fallback.yaml"
    cache.write_text(ALLOW_POLICY, encoding="utf-8")
    fallback.write_text(DENY_POLICY, encoding="utf-8")

    gateway = Gateway.from_policy_source(
        "http://127.0.0.1:9/policy.yaml",
        cache_file=cache,
        fallback_policy_file=fallback,
        refresh_seconds=60,
    )
    response = gateway.chat(
        GatewayRequest(
            tenant="acme",
            app="fallback-cache-test",
            user={"role": "support_agent"},
            context={"region": "us", "risk": "low", "task_type": "support"},
            messages=[{"role": "user", "content": "Summarize this ticket."}],
        )
    )

    assert response.policy.decision.value in {"allow", "conditional_allow"}
    assert gateway.policy_engine.snapshot is not None
    assert "cached:" in gateway.policy_engine.snapshot.source


def test_checksum_mismatch_logs_critical_and_uses_valid_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    cache = tmp_path / "policy-cache.yaml"
    cache.write_text(ALLOW_POLICY, encoding="utf-8")
    expected_sha = hashlib.sha256(ALLOW_POLICY.encode("utf-8")).hexdigest()
    source = HttpPolicySource(
        "https://policy.example.com/policyaware.yaml",
        cache_file=cache,
        expected_sha256=expected_sha,
    )

    monkeypatch.setattr(source, "_download_text", lambda: DENY_POLICY)

    with caplog.at_level(logging.CRITICAL, logger="policyaware.policy_source"):
        snapshot = source.load()

    assert "cached:" in snapshot.source
    assert snapshot.policy["rules"][0]["name"] == "allow_support"
    assert cache.read_text(encoding="utf-8") == ALLOW_POLICY
    assert "Policy checksum validation failed" in caplog.text


def test_remote_policy_without_cache_or_fallback_fails_closed_on_startup() -> None:
    with pytest.raises(PolicySourceError):
        DynamicPolicyEngine(FailingPolicySource(), refresh_seconds=0, fail_closed=True)


def test_gateway_from_policy_source_uses_fallback_policy_file(tmp_path: Path) -> None:
    fallback = tmp_path / "fallback.yaml"
    fallback.write_text(DENY_POLICY, encoding="utf-8")

    gateway = Gateway.from_policy_source(
        tmp_path / "missing-remote-policy.yaml",
        fallback_policy_file=fallback,
        refresh_seconds=60,
    )

    assert gateway.policy_engine.snapshot is not None
    assert "fallback_after" in gateway.policy_engine.snapshot.source


def test_dynamic_policy_refresh_swaps_snapshot_and_engine_atomically() -> None:
    engine = DynamicPolicyEngine(IncrementingPolicySource(), refresh_seconds=0, fail_closed=True)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: engine.refresh(force=True), range(50)))

    assert engine.snapshot is not None
    assert engine._engine is not None
    assert engine.snapshot.policy["id"] == engine._engine.policy["id"]


def test_dynamic_policy_refresh_releases_old_engine_reference() -> None:
    engine = DynamicPolicyEngine(IncrementingPolicySource(), refresh_seconds=0, fail_closed=True)
    old_engine = engine._engine
    assert old_engine is not None
    old_engine_ref = weakref.ref(old_engine)

    engine.refresh(force=True)

    assert engine._engine is not old_engine
    del old_engine
    gc.collect()
    assert old_engine_ref() is None


def test_dynamic_policy_refresh_uses_backoff_after_failure() -> None:
    source = FailsAfterFirstSuccessPolicySource()
    engine = DynamicPolicyEngine(
        source,
        refresh_seconds=0,
        fail_closed=False,
        retry_base_seconds=5.0,
        retry_max_seconds=30.0,
        retry_jitter_seconds=0.0,
    )

    assert source.calls == 1
    assert engine.refresh() is False
    assert source.calls == 2
    next_attempt = engine._next_attempt

    assert next_attempt > time.time()
    assert engine.refresh() is False
    assert source.calls == 2


class FailingPolicySource(PolicySource):
    def load(self):
        raise PolicySourceError("simulated policy source outage")


class IncrementingPolicySource(PolicySource):
    def __init__(self) -> None:
        self._lock = Lock()
        self._version = 0

    def load(self) -> PolicySourceSnapshot:
        with self._lock:
            self._version += 1
            version = self._version
        # Encourage thread interleaving around policy construction.
        time.sleep(0.001)
        policy = {
            "id": f"policy_{version}",
            "default": "deny",
            "rules": [
                {
                    "name": "allow_support",
                    "effect": "allow",
                    "when": {"user.role": "support_agent"},
                }
            ],
        }
        return PolicySourceSnapshot(
            source=f"memory:{version}",
            version=str(version),
            loaded_at=time.time(),
            policy=policy,
            sha256=str(version),
        )


class FailsAfterFirstSuccessPolicySource(PolicySource):
    def __init__(self) -> None:
        self.calls = 0

    def load(self) -> PolicySourceSnapshot:
        self.calls += 1
        if self.calls > 1:
            raise PolicySourceError("simulated policy source slowdown")
        return PolicySourceSnapshot(
            source="memory:initial",
            version="1",
            loaded_at=time.time(),
            policy={
                "default": "deny",
                "rules": [
                    {
                        "name": "allow_support",
                        "effect": "allow",
                        "when": {"user.role": "support_agent"},
                    }
                ],
            },
            sha256="1",
        )
