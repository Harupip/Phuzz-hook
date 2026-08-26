from __future__ import annotations

from pathlib import Path
from typing import Any

from seed_generation.skeleton.common_generator import SeedGeneratorBase
from .input_extractor import InputSignatureExtractor
from .source_resolver import SourcePathResolver


class StaticSeedGenerator(SeedGeneratorBase):
    """Generate seeds with plugin-source parameter extraction."""

    def __init__(
        self,
        input_extractor: InputSignatureExtractor | None = None,
        *,
        container_source_root: str | Path | None = None,
        host_source_root: str | Path | None = None,
        source_root: str | Path | None = None,
        unresolved_source_reason: str | None = None,
    ) -> None:
        resolver = SourcePathResolver(
            container_source_root=container_source_root,
            host_source_root=host_source_root,
            source_root=source_root,
            unresolved_reason=unresolved_source_reason,
        )
        self.input_extractor = input_extractor or InputSignatureExtractor(source_resolver=resolver)

    def _extract_input_params(self, registered_entry: dict[str, Any]) -> dict[str, Any]:
        return self.input_extractor.extract(registered_entry)
