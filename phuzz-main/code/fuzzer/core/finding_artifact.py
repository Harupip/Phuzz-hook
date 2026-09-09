from __future__ import annotations

import json
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def build_finding_record(candidate: Any, *, vuln_type: str, run_id: str) -> dict[str, Any]:
    mutated_param_type = getattr(candidate, "mutated_param_type", None)
    mutated_param_name = getattr(candidate, "mutated_param_name", None)
    fuzz_params = getattr(candidate, "fuzz_params", {}) or {}
    bucket = fuzz_params.get(mutated_param_type, {}) if mutated_param_type else {}
    payload = bucket.get(mutated_param_name) if isinstance(bucket, dict) else None

    return {
        "vuln_type": str(vuln_type),
        "run_id": str(run_id),
        "coverage_id": str(getattr(candidate, "coverage_id", "")),
        "fuzzer_id": getattr(candidate, "fuzzer_id", None),
        "mutated_param_type": mutated_param_type,
        "mutated_param_name": mutated_param_name,
        "payload": payload,
        "mutation_source": getattr(candidate, "mutation_source", None),
        "http_target": getattr(candidate, "http_target", ""),
        "http_method": getattr(candidate, "http_method", ""),
        "hook_request_id": getattr(candidate, "hook_request_id", ""),
        "fuzz_params": fuzz_params,
        "fixed_params": getattr(candidate, "fixed_params", {}) or {},
    }


def write_finding_artifact(
    path: str | os.PathLike[str],
    *,
    run_id: str,
    fuzzer_id: Any,
    findings: Iterable[dict[str, Any]],
) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f"{output_path.name}.{os.getpid()}.tmp")
    payload = {
        "schema_version": 1,
        "run_id": str(run_id),
        "fuzzer_id": fuzzer_id,
        "findings": list(findings),
    }
    try:
        temporary_path.write_text(
            json.dumps(payload, indent=2, default=str),
            encoding="utf-8",
        )
        temporary_path.replace(output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
