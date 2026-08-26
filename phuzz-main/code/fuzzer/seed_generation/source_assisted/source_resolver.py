from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SourceResolution:
    source_file: str
    status: str
    resolved_source_file: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "source_file": self.source_file,
            "status": self.status,
            "resolved_source_file": self.resolved_source_file,
        }
        if self.reason:
            result["reason"] = self.reason
        return result


class SourcePathResolver:
    def __init__(
        self,
        *,
        container_source_root: str | Path | None = None,
        host_source_root: str | Path | None = None,
        source_root: str | Path | None = None,
        unresolved_reason: str | None = None,
    ) -> None:
        self.container_source_root = self._normalize_container_root(container_source_root)
        self.host_source_root = Path(host_source_root) if host_source_root else None
        self.source_root = Path(source_root) if source_root else self.host_source_root
        self.unresolved_reason = str(unresolved_reason or "").strip() or None

    def resolve(self, source_file: str | Path | None) -> SourceResolution:
        raw_source = str(source_file or "").strip()
        if not raw_source:
            return SourceResolution("", "unresolved", None, self.unresolved_reason)

        local_path = Path(raw_source)
        if local_path.exists() and local_path.is_file():
            return SourceResolution(raw_source, "resolved", str(local_path.resolve()))

        mapped = self._resolve_from_explicit_roots(raw_source)
        if mapped is not None:
            return SourceResolution(raw_source, "zip_mapped", str(mapped.resolve()))

        mapped = self._resolve_from_source_root(raw_source)
        if mapped is not None:
            return SourceResolution(raw_source, "zip_mapped", str(mapped.resolve()))

        return SourceResolution(raw_source, "unresolved", None, self.unresolved_reason)

    def _resolve_from_explicit_roots(self, raw_source: str) -> Path | None:
        if not self.container_source_root or self.host_source_root is None:
            return None

        normalized = self._normalize_container_path(raw_source)
        prefix = self.container_source_root.rstrip("/") + "/"
        if normalized == self.container_source_root:
            relative = ""
        elif normalized.startswith(prefix):
            relative = normalized[len(prefix) :]
        else:
            return None

        candidate = self.host_source_root.joinpath(*[part for part in relative.split("/") if part])
        return candidate if candidate.exists() and candidate.is_file() else None

    def _resolve_from_source_root(self, raw_source: str) -> Path | None:
        if self.source_root is None:
            return None

        normalized = self._normalize_container_path(raw_source)
        marker = "/wp-content/plugins/"
        if marker not in normalized:
            return None

        suffix = normalized.split(marker, 1)[1]
        parts = [part for part in suffix.split("/") if part]
        if len(parts) < 2:
            return None

        plugin_relative = parts[1:]
        candidates = [
            self.source_root.joinpath(*plugin_relative),
            self.source_root.joinpath(*parts),
        ]
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return candidate
        return None

    def _normalize_container_root(self, value: str | Path | None) -> str:
        if value is None:
            return ""
        return self._normalize_container_path(str(value)).rstrip("/")

    def _normalize_container_path(self, value: str) -> str:
        return value.replace("\\", "/").rstrip("/")
