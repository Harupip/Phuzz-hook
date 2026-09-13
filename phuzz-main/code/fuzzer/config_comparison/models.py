from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NO_REFERENCE = "NO_REFERENCE"
    AMBIGUOUS = "AMBIGUOUS"
    INVALID = "INVALID"


class DifferenceKind(str, Enum):
    MISSING_PARAMETER = "MISSING_PARAMETER"
    UNEXPECTED_PARAMETER = "UNEXPECTED_PARAMETER"
    VALUE_MISMATCH = "VALUE_MISMATCH"
    SEED_MISMATCH = "SEED_MISMATCH"
    CLASSIFICATION_MISMATCH = "CLASSIFICATION_MISMATCH"
    METHOD_MISMATCH = "METHOD_MISMATCH"
    TARGET_MISMATCH = "TARGET_MISMATCH"
    SOURCE_MISMATCH = "SOURCE_MISMATCH"
    DUPLICATE_PARAMETER = "DUPLICATE_PARAMETER"
    INVALID_CONFIG = "INVALID_CONFIG"


def _json_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return [_json_safe(item) for item in sorted(value, key=repr)]
    return copy.deepcopy(value)


@dataclass(frozen=True)
class Difference:
    kind: DifferenceKind
    path: str
    expected: Any = None
    actual: Any = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "kind": self.kind.value,
            "path": self.path,
            "expected": _json_safe(self.expected),
            "actual": _json_safe(self.actual),
        }
        if self.reason is not None:
            result["reason"] = self.reason
        return result


@dataclass(frozen=True)
class ConfigError:
    kind: DifferenceKind
    path: str
    message: str
    side: str = "config"
    input_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "kind": self.kind.value,
            "path": self.path,
            "message": self.message,
            "side": self.side,
        }
        if self.input_index is not None:
            result["input_index"] = self.input_index
        return result


@dataclass
class NormalizedConfig:
    target: str
    methods: tuple[str, ...]
    parameters: dict[str, dict[str, dict[str, Any]]]
    selectors: dict[str, dict[str, frozenset[str]]]
    section_extras: dict[str, dict[str, Any]] = field(default_factory=dict)
    extras: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _json_safe({
            "target": self.target,
            "methods": self.methods,
            "parameters": self.parameters,
            "selectors": self.selectors,
            "section_extras": self.section_extras,
            "extras": self.extras,
        })


@dataclass
class NormalizationResult:
    config: NormalizedConfig | None
    errors: list[ConfigError] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config.to_dict() if self.config is not None else None,
            "errors": [error.to_dict() for error in self.errors],
        }


@dataclass(frozen=True)
class RequestIdentity:
    family: str
    methods: tuple[str, ...]
    endpoint: str
    action: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "methods": list(self.methods),
            "endpoint": self.endpoint,
            "action": self.action,
        }


@dataclass
class CompareResult:
    status: Status
    differences: list[Difference] = field(default_factory=list)
    errors: list[ConfigError] = field(default_factory=list)
    actual_index: int | None = None
    reference_indices: list[int] | None = None

    @property
    def matched(self) -> bool:
        return self.status is Status.MATCH

    def to_dict(self) -> dict[str, Any]:
        result = {
            "status": self.status.value,
            "matched": self.matched,
            "differences": [difference.to_dict() for difference in self.differences],
            "errors": [error.to_dict() for error in self.errors],
        }
        if self.actual_index is not None:
            result["actual_index"] = self.actual_index
        if self.reference_indices is not None:
            result["reference_indices"] = list(self.reference_indices)
        return result


@dataclass
class PreparedReferences:
    policy: Any
    normalized_references: list[NormalizedConfig | None]
    index: dict[RequestIdentity, list[int]]
    reference_errors: list[ConfigError] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.reference_errors
