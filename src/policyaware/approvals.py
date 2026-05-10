from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from urllib import request as urlrequest

from policyaware.models import ApprovalRequest, GatewayRequest, PolicyDecision


class ApprovalClient(ABC):
    @abstractmethod
    def submit(self, request: GatewayRequest, decision: PolicyDecision) -> ApprovalRequest:
        raise NotImplementedError


class NoopApprovalClient(ApprovalClient):
    def submit(self, request: GatewayRequest, decision: PolicyDecision) -> ApprovalRequest:
        return ApprovalRequest(
            tenant=request.tenant,
            app=request.app,
            user=request.user,
            decision=decision,
            request_snapshot=request.model_dump(mode="json"),
        )


class FileApprovalClient(ApprovalClient):
    def __init__(self, path: str | Path = ".policyaware/approvals.jsonl"):
        self.path = Path(path)

    def submit(self, request: GatewayRequest, decision: PolicyDecision) -> ApprovalRequest:
        approval = ApprovalRequest(
            tenant=request.tenant,
            app=request.app,
            user=request.user,
            decision=decision,
            request_snapshot=request.model_dump(mode="json"),
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(approval.model_dump_json() + "\n")
        return approval


class WebhookApprovalClient(ApprovalClient):
    def __init__(self, url: str, timeout_seconds: int = 15):
        self.url = url
        self.timeout_seconds = timeout_seconds

    def submit(self, request: GatewayRequest, decision: PolicyDecision) -> ApprovalRequest:
        approval = ApprovalRequest(
            tenant=request.tenant,
            app=request.app,
            user=request.user,
            decision=decision,
            request_snapshot=request.model_dump(mode="json"),
        )
        body = json.dumps(approval.model_dump(mode="json")).encode("utf-8")
        req = urlrequest.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlrequest.urlopen(req, timeout=self.timeout_seconds):
            pass
        return approval
