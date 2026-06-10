from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StaticParam:
    name: str
    source: str
    source_file: str
    source_line: int
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "confidence": self.confidence,
        }


@dataclass
class StaticEndpoint:
    kind: str
    target: str
    method: str
    auth_mode: str
    callback: str | None
    params: list[StaticParam] = field(default_factory=list)
    fixed_params: dict[str, str] = field(default_factory=dict)
    fuzz_params: list[str] = field(default_factory=list)
    sink_hints: list[str] = field(default_factory=list)
    source_file: str = ""
    source_line: int = 0
    confidence: str = "high"
    unresolved: bool = False
    hook_name: str | None = None
    action: str | None = None
    route: str | None = None
    expression_text: str | None = None
    namespace: str | None = None
    permission_callback: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "target": self.target,
            "method": self.method,
            "auth_mode": self.auth_mode,
            "callback": self.callback,
            "params": [item.to_dict() for item in self.params],
            "fixed_params": self.fixed_params,
            "fuzz_params": self.fuzz_params,
            "sink_hints": self.sink_hints,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "confidence": self.confidence,
            "unresolved": self.unresolved,
        }
        for key in ("hook_name", "action", "route", "expression_text", "namespace", "permission_callback"):
            value = getattr(self, key)
            if value not in (None, ""):
                payload[key] = value
        return payload
