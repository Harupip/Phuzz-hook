from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


PARAMETER_SOURCES = frozenset({"headers", "cookies", "query_params", "body_params"})

SEMANTIC_IGNORED_PATHS = frozenset({
    "/print_timestamps",
    "/run_id",
    "/generated_at",
    "/artifact_path",
    "/output_dir",
    "/config_type",
    "/entrypoint_type",
    "/metadata/run_id",
    "/metadata/generated_at",
    "/metadata/artifact_path",
    "/metadata/generated_by",
    "/metadata/generated_reason",
    "/metadata/candidate_id",
    "/metadata/callback_id",
    "/metadata/callback_repr",
    "/metadata/callback_source_file",
    "/metadata/callback_start_line",
    "/metadata/source_file",
    "/metadata/source_line",
    "/metadata/entrypoint_type",
    "/metadata/fuzzing_ready",
    "/metadata/setup_required",
    "/metadata/manual_analysis",
    "/metadata/missing_requirements",
    "/metadata/method_source",
    "/metadata/method_confidence",
    "/metadata/method_evidence",
    "/metadata/candidate_methods",
    "/metadata/method_status",
    "/metadata/observed_request_method",
    "/metadata/route_declared_methods",
    "/metadata/seed_variant_id",
    "/metadata/probe_variant",
    "/metadata/probe_request",
    "/metadata/route",
})


def _validate_json_pointer(path: str) -> None:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("ignored metadata paths must be JSON Pointers")
    if path == "/" or path.startswith(("/target", "/methods")):
        raise ValueError("cannot ignore required request paths")
    for source in PARAMETER_SOURCES:
        if path == f"/{source}" or path.startswith(f"/{source}/"):
            raise ValueError("cannot ignore required request paths")


@dataclass(frozen=True)
class ComparisonPolicy:
    mode: str = "strict"
    allowed_extra_parameters: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    ignored_metadata_paths: frozenset[str] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.mode, str):
            raise ValueError("policy mode must be strict or semantic")
        if self.mode == "effective":
            raise ValueError("effective policy is not supported in V1")
        if self.mode not in {"strict", "semantic"}:
            raise ValueError("policy mode must be strict or semantic")

        allowed: set[tuple[str, str]] = set()
        for item in self.allowed_extra_parameters:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise ValueError("allowed extra parameters must be (source, name) pairs")
            source, name = item
            if not isinstance(source, str) or source not in PARAMETER_SOURCES or not isinstance(name, str) or not name:
                raise ValueError("allowed extra parameters must use a valid source and name")
            allowed.add((source, name))
        object.__setattr__(self, "allowed_extra_parameters", frozenset(allowed))

        custom = set(self.ignored_metadata_paths or ())
        for path in custom:
            _validate_json_pointer(path)
        ignored = set(SEMANTIC_IGNORED_PATHS if self.mode == "semantic" else ())
        ignored.update(custom)
        object.__setattr__(self, "ignored_metadata_paths", frozenset(ignored))

    def ignores(self, path: str) -> bool:
        return path in self.ignored_metadata_paths
