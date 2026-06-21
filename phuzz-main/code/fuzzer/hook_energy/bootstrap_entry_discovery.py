from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy import bootstrap_probe_runner, entry_classifier, seed_validator
from hook_energy.phuzz_config_writer import write_candidate_configs


FINAL_REPORT = "bootstrap_entry_discovery_report.json"
RUNTIME_REGISTRY = "runtime_hook_registry.json"
LIMITATIONS = [
    "Generated configs are written as artifacts and are not auto-imported into PHUZZ live queue.",
    "Only direct HTTP candidates are converted to PHUZZ configs.",
    "Setup-required candidates are reported but not replayed automatically.",
]


@dataclass(frozen=True)
class PipelineArtifacts:
    bootstrap_probe_report: Path
    runtime_hook_registry: Path
    entrypoint_candidates: Path
    direct_http_candidates: Path
    setup_required_candidates: Path
    non_entry_hooks: Path
    generated_phuzz_configs_dir: Path
    validation_results_dir: Path


def run_discovery_pipeline(
    *,
    base_url: str,
    hook_coverage_dir: str | Path,
    output_dir: str | Path,
    coverage_file: str | Path | None,
    max_validate: int,
    timeout: float,
    pretty: bool = False,
) -> dict[str, Any]:
    started_at = _utc_now()
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    generated_config_dir = output_path / "generated_phuzz_configs"
    validation_dir = output_path / "validation_results"
    generated_config_dir.mkdir(parents=True, exist_ok=True)
    validation_dir.mkdir(parents=True, exist_ok=True)

    bootstrap_report = bootstrap_probe_runner.run_bootstrap_probes(
        base_url=base_url,
        hook_coverage_dir=hook_coverage_dir,
        timeout=timeout,
    )
    bootstrap_report_path = bootstrap_probe_runner.write_report(bootstrap_report, output_path)

    runtime_registry_path = resolve_runtime_registry(coverage_file, hook_coverage_dir, output_path, pretty=pretty)
    callbacks, _ = entry_classifier.load_registry(runtime_registry_path, "auto")
    classification_report = entry_classifier.classify_callbacks(callbacks, str(runtime_registry_path))
    classification_paths = entry_classifier.write_classification_artifacts(classification_report, output_path, pretty=pretty)

    generated_configs = write_candidate_configs(
        classification_paths["direct_http_candidates"],
        output_dir=generated_config_dir,
        target_base=base_url,
        pretty=pretty,
    )

    direct_candidates = _load_candidates(classification_paths["direct_http_candidates"])
    selected = select_candidates_for_validation(direct_candidates, max_validate=max_validate)
    config_by_candidate = {item["candidate_id"]: item["path"] for item in generated_configs}
    validation_summaries = []
    for candidate in selected:
        candidate_id = str(candidate.get("candidate_id") or "candidate")
        result = seed_validator.validate_candidate(
            candidate=candidate,
            base_url=base_url,
            hook_coverage_dir=hook_coverage_dir,
            timeout=timeout,
        )
        validation_file = validation_dir / f"{_safe_filename(candidate_id)}.validation_result.json"
        seed_validator.write_validation_result(result, validation_file, pretty=pretty)
        validation_summaries.append(
            {
                "candidate_id": candidate_id,
                "hook_name": candidate.get("hook_name"),
                "entry_type": candidate.get("entry_type"),
                "config_file": config_by_candidate.get(candidate_id),
                "validation_file": validation_file,
                "expected_hook_fired": bool(result.get("result", {}).get("expected_hook_fired")),
                "expected_callback_reached": bool(result.get("result", {}).get("expected_callback_reached")),
            }
        )

    artifacts = PipelineArtifacts(
        bootstrap_probe_report=bootstrap_report_path,
        runtime_hook_registry=runtime_registry_path,
        entrypoint_candidates=classification_paths["entrypoint_candidates"],
        direct_http_candidates=classification_paths["direct_http_candidates"],
        setup_required_candidates=classification_paths["setup_required_candidates"],
        non_entry_hooks=classification_paths["non_entry_hooks"],
        generated_phuzz_configs_dir=generated_config_dir,
        validation_results_dir=validation_dir,
    )
    runtime_registry = _load_json(runtime_registry_path)
    final_report = build_final_report(
        base_url=base_url,
        started_at=started_at,
        finished_at=_utc_now(),
        output_dir=output_path,
        artifacts=artifacts,
        bootstrap_report=bootstrap_report,
        runtime_registry=runtime_registry if isinstance(runtime_registry, Mapping) else {},
        classification_report=classification_report,
        generated_configs=generated_configs,
        validation_summaries=validation_summaries,
    )
    (output_path / FINAL_REPORT).write_text(
        json.dumps(final_report, indent=2 if pretty else None, ensure_ascii=False),
        encoding="utf-8",
    )
    return final_report


def resolve_runtime_registry(
    coverage_file: str | Path | None,
    hook_coverage_dir: str | Path,
    output_dir: str | Path,
    *,
    pretty: bool = False,
) -> Path:
    if coverage_file is not None:
        payload = _load_json(Path(coverage_file))
        normalized = _normalize_registry_payload(payload, source="total_coverage")
    else:
        total_coverage = Path(hook_coverage_dir) / "total_coverage.json"
        if total_coverage.exists():
            payload = _load_json(total_coverage)
            normalized = _normalize_registry_payload(payload, source="total_coverage")
        else:
            normalized = _registry_from_request_artifacts(Path(hook_coverage_dir))

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    registry_path = output_path / RUNTIME_REGISTRY
    registry_path.write_text(
        json.dumps(normalized, indent=2 if pretty else None, ensure_ascii=False),
        encoding="utf-8",
    )
    return registry_path


def select_candidates_for_validation(candidates: list[dict[str, Any]], *, max_validate: int) -> list[dict[str, Any]]:
    unauthenticated = []
    authenticated = []
    remaining = []
    for candidate in candidates:
        hook_name = str(candidate.get("hook_name") or "")
        if (
            hook_name.startswith("wp_ajax_nopriv_")
            or hook_name.startswith("admin_post_nopriv_")
            or hook_name == "heartbeat_nopriv_received"
        ):
            unauthenticated.append(candidate)
        elif (
            hook_name.startswith("wp_ajax_")
            or hook_name.startswith("admin_post_")
            or hook_name.startswith("admin_action_")
        ):
            authenticated.append(candidate)
        else:
            remaining.append(candidate)
    return (unauthenticated + authenticated + remaining)[: max(0, max_validate)]


def build_final_report(
    *,
    base_url: str,
    started_at: str,
    finished_at: str,
    output_dir: Path,
    artifacts: PipelineArtifacts,
    bootstrap_report: Mapping[str, Any],
    runtime_registry: Mapping[str, Any],
    classification_report: Mapping[str, Any],
    generated_configs: list[Mapping[str, Any]],
    validation_summaries: list[Mapping[str, Any]],
) -> dict[str, Any]:
    counts = classification_report.get("counts", {})
    return {
        "schema_version": 1,
        "base_url": base_url,
        "started_at": started_at,
        "finished_at": finished_at,
        "artifacts": {
            "bootstrap_probe_report": _relative(output_dir, artifacts.bootstrap_probe_report),
            "runtime_hook_registry": _relative(output_dir, artifacts.runtime_hook_registry),
            "entrypoint_candidates": _relative(output_dir, artifacts.entrypoint_candidates),
            "direct_http_candidates": _relative(output_dir, artifacts.direct_http_candidates),
            "setup_required_candidates": _relative(output_dir, artifacts.setup_required_candidates),
            "non_entry_hooks": _relative(output_dir, artifacts.non_entry_hooks),
            "generated_phuzz_configs_dir": _relative(output_dir, artifacts.generated_phuzz_configs_dir),
            "validation_results_dir": _relative(output_dir, artifacts.validation_results_dir),
        },
        "counts": {
            "probes": len(bootstrap_report.get("probes", [])) if isinstance(bootstrap_report.get("probes"), list) else 0,
            "probe_artifacts": int(bootstrap_report.get("summary", {}).get("artifacts_created", 0)),
            "registered_callbacks": len(runtime_registry.get("registered_callbacks", [])),
            "executed_callbacks": len(runtime_registry.get("executed_callbacks", [])),
            "direct_http_candidates": int(counts.get("direct_http", 0)) if isinstance(counts, Mapping) else 0,
            "setup_required_candidates": int(counts.get("setup_required", 0)) if isinstance(counts, Mapping) else 0,
            "non_entry_hooks": int(counts.get("non_entry", 0)) if isinstance(counts, Mapping) else 0,
            "generated_phuzz_configs": len(generated_configs),
            "validated_candidates": len(validation_summaries),
            "expected_hook_fired": sum(1 for item in validation_summaries if item.get("expected_hook_fired")),
            "expected_callback_reached": sum(1 for item in validation_summaries if item.get("expected_callback_reached")),
        },
        "validated": [
            {
                "candidate_id": item.get("candidate_id"),
                "hook_name": item.get("hook_name"),
                "entry_type": item.get("entry_type"),
                "config_file": _relative(output_dir, item.get("config_file")),
                "validation_file": _relative(output_dir, item.get("validation_file")),
                "expected_hook_fired": bool(item.get("expected_hook_fired")),
                "expected_callback_reached": bool(item.get("expected_callback_reached")),
            }
            for item in validation_summaries
        ],
        "limitations": LIMITATIONS,
    }


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run HookPhuzz bootstrap entry discovery pipeline.")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--hook-coverage-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--coverage-file")
    parser.add_argument("--max-validate", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--pretty", action="store_true")
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    try:
        report = run_discovery_pipeline(
            base_url=args.base_url,
            hook_coverage_dir=args.hook_coverage_dir,
            output_dir=args.output_dir,
            coverage_file=args.coverage_file,
            max_validate=args.max_validate,
            timeout=args.timeout,
            pretty=args.pretty,
        )
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 2
    counts = report["counts"]
    print(
        "Bootstrap entry discovery summary: "
        f"direct_http={counts['direct_http_candidates']} "
        f"configs={counts['generated_phuzz_configs']} "
        f"validated={counts['validated_candidates']} "
        f"report={Path(args.output_dir) / FINAL_REPORT}"
    )
    return 0


def _normalize_registry_payload(payload: Any, *, source: str) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        payload = {}
    if isinstance(payload.get("callbacks"), list):
        registered_list = [dict(item) for item in payload["callbacks"] if isinstance(item, Mapping)]
        registered_map = _list_to_callback_map(registered_list)
        return _registry_payload(source="hook_gap_report", registered=registered_map, executed={}, blindspots={})

    data = payload.get("data", {}) if isinstance(payload.get("data"), Mapping) else {}
    registered = _normalize_callback_map(data.get("registered_callbacks", payload.get("registered_callbacks", {})))
    executed = _normalize_callback_map(data.get("executed_callbacks", payload.get("executed_callbacks", {})))
    blindspots = _normalize_callback_map(data.get("blindspot_callbacks", payload.get("blindspot_callbacks", {})))
    return _registry_payload(source=source, registered=registered, executed=executed, blindspots=blindspots)


def _registry_from_request_artifacts(hook_coverage_dir: Path) -> dict[str, Any]:
    registered: dict[str, dict[str, Any]] = {}
    executed: dict[str, dict[str, Any]] = {}
    blindspots: dict[str, dict[str, Any]] = {}
    requests_dir = hook_coverage_dir / "requests"
    for artifact in sorted(requests_dir.glob("*.json")) if requests_dir.exists() else []:
        payload = _load_json(artifact)
        if not isinstance(payload, Mapping):
            continue
        coverage = payload.get("hook_coverage", {})
        if not isinstance(coverage, Mapping):
            coverage = {}
        registered.update(_normalize_callback_map(coverage.get("registered_callbacks", {})))
        executed.update(_normalize_callback_map(coverage.get("executed_callbacks", {})))
        blindspots.update(_normalize_callback_map(coverage.get("blindspot_callbacks", {})))
    return _registry_payload(source="request_artifacts", registered=registered, executed=executed, blindspots=blindspots)


def _registry_payload(
    *,
    source: str,
    registered: dict[str, dict[str, Any]],
    executed: dict[str, dict[str, Any]],
    blindspots: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source": source,
        "generated_at": _utc_now(),
        "registered_callbacks": list(registered.values()),
        "executed_callbacks": list(executed.values()),
        "blindspot_callbacks": list(blindspots.values()),
        "data": {
            "registered_callbacks": registered,
            "executed_callbacks": executed,
            "blindspot_callbacks": blindspots,
        },
    }


def _normalize_callback_map(value: Any) -> dict[str, dict[str, Any]]:
    if isinstance(value, Mapping):
        normalized = {}
        for key, item in value.items():
            if not isinstance(item, Mapping):
                continue
            row = dict(item)
            row.setdefault("callback_id", str(key))
            normalized[str(row["callback_id"])] = row
        return normalized
    if isinstance(value, list):
        return _list_to_callback_map([dict(item) for item in value if isinstance(item, Mapping)])
    return {}


def _list_to_callback_map(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    normalized = {}
    for index, row in enumerate(rows, start=1):
        callback_id = str(row.get("callback_id") or f"callback-{index}")
        row["callback_id"] = callback_id
        normalized[callback_id] = row
    return normalized


def _load_candidates(path: Path) -> list[dict[str, Any]]:
    payload = _load_json(path)
    candidates = payload.get("candidates", []) if isinstance(payload, Mapping) else []
    return [dict(item) for item in candidates if isinstance(item, Mapping)]


def _load_json(path: Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}


def _relative(base: Path, path: Any) -> str | None:
    if path is None:
        return None
    resolved = Path(path)
    try:
        return resolved.relative_to(base).as_posix()
    except ValueError:
        return resolved.as_posix()


def _safe_filename(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value).strip("._-") or "candidate"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
