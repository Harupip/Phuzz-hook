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
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportedSeedResult:
    authenticated_queue: list[ImportedSeedRequest] = field(default_factory=list)
    unauthenticated_queue: list[ImportedSeedRequest] = field(default_factory=list)
    manual_analysis_queue: list[dict[str, Any]] = field(default_factory=list)


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
