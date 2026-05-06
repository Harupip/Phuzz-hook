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
