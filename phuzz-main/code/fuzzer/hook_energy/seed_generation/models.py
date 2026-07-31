from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ImportedSeedRequest:
    request_id: str
    source: str
    http_method: str
    path: str
    content_type: str
    body: dict[str, Any]
    auth_mode: str
    method_source: str = "legacy_artifact"
    method_confidence: str = "low"
    method_evidence: Any = None
    query_params: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, Any] = field(default_factory=dict)
    cookies: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "source": self.source,
            "http_method": self.http_method,
            "method_source": self.method_source,
            "method_confidence": self.method_confidence,
            "method_evidence": self.method_evidence,
            "path": self.path,
            "content_type": self.content_type,
            "body": self.body,
            "query_params": self.query_params,
            "headers": self.headers,
            "cookies": self.cookies,
            "auth_mode": self.auth_mode,
            "metadata": self.metadata,
        }


@dataclass
class ImportedSeedResult:
    authenticated_queue: list[ImportedSeedRequest] = field(default_factory=list)
    unauthenticated_queue: list[ImportedSeedRequest] = field(default_factory=list)
    manual_analysis_queue: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class ManualAnalysisEntry:
    callback_id: str
    hook_name: str
    callback_name: str
    status: str
    is_active: bool
    direct_http_supported: bool
    generation_status: str
    seed_priority: str
    target_family: str
    source_file: str | None = None
    source_line: int | None = None
    accepted_args: int | None = None
