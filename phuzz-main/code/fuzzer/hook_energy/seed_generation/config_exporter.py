from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


class SeedConfigSkip(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def build_config_for_seed_item(
    seed_item: Mapping[str, Any],
    *,
    target_base: str = "http://web",
) -> tuple[str, dict[str, Any]]:
    seed = seed_item.get("seed")
    if not isinstance(seed, Mapping):
        raise SeedConfigSkip("missing_seed")

    auth_mode = str(seed.get("auth_mode", "")).strip()
    if auth_mode not in {"authenticated", "unauth-capable"}:
        raise SeedConfigSkip("unsupported_auth_mode")

    methods = _seed_methods(seed)
    path = str(seed.get("path", "")).strip()
    body = seed.get("body")
    if not methods or not path or not isinstance(body, Mapping):
        raise SeedConfigSkip("malformed_seed")

    config: dict[str, Any] = {
        "target": _join_target(target_base, path),
        "methods": methods,
        "print_timestamps": True,
    }
    entrypoint_type = _entrypoint_type_for_seed(seed_item, seed, path)
    if entrypoint_type:
        config["entrypoint_type"] = entrypoint_type

    fixed_params = _string_set(seed.get("fixed_params", []))
    fuzzable_params = _string_set(seed.get("fuzzable_params", []))

    sections = (
        ("body", "body_params"),
        ("query_params", "query_params"),
        ("headers", "headers"),
        ("cookies", "cookies"),
    )
    fuzz_count = 0
    for seed_key, config_key in sections:
        values = seed.get(seed_key, {})
        if not isinstance(values, Mapping) or not values:
            continue

        section = _build_param_section(
            values,
            fixed_params=fixed_params,
            fuzzable_params=fuzzable_params,
        )
        config[config_key] = section
        if config_key in {"body_params", "query_params"}:
            fuzz_count += len(section["fuzz"])

    config['config_type'] = 'fuzzing_ready' if fuzz_count else 'replay_only'
    discovered_file_params = seed.get('discovered_file_params', [])
    if not isinstance(discovered_file_params, list):
        discovered_file_params = []
    config['metadata'] = _metadata_for_seed_item(
        seed_item,
        seed,
        entrypoint_type=entrypoint_type,
        fuzzing_ready=bool(fuzz_count),
        discovered_file_params=discovered_file_params,
    )
    return _build_file_slug(seed_item), config


def export_seed_configs(
    seed_report: Mapping[str, Any],
    *,
    output_config_dir: str | Path,
    summary_path: str | Path | None = None,
    target_base: str = "http://web",
    runtime_param_discoveries: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, list[dict[str, str]]]:
    output_dir = Path(output_config_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {"generated": [], "skipped": []}
    discoveries = list(runtime_param_discoveries or [])
    consumed_discoveries: set[int] = set()
    suggestions = seed_report.get("suggested_seeds", [])
    if not isinstance(suggestions, list):
        raise ValueError("suggested_seeds.json must contain a suggested_seeds array")

    for item in suggestions:
        if not isinstance(item, Mapping):
            summary["skipped"].append({"hook_name": "", "callback_id": "", "reason": "malformed_item"})
            continue

        hook_name = str(item.get("hook_name", ""))
        callback_id = str(item.get("callback_id", ""))
        try:
            file_slug, config = build_config_for_seed_item(item, target_base=target_base)
        except SeedConfigSkip as exc:
            summary["skipped"].append(_skipped_row(item, hook_name, callback_id, exc.reason))
            continue

        matching_discoveries = [
            discovery
            for index, discovery in enumerate(discoveries)
            if _runtime_discovery_matches_seed(discovery, item)
            and not consumed_discoveries.add(index)
        ]
        merge_runtime_param_discoveries(config, item, matching_discoveries)

        config_path = output_dir / f"{file_slug}.json"
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        generated_row = {
            "config_slug": _build_config_slug(output_dir, file_slug),
            "config_path": str(config_path),
            "hook_name": hook_name,
            "callback_id": callback_id,
        }
        entrypoint_type = str(config.get("entrypoint_type", "")).strip()
        if entrypoint_type:
            generated_row["entrypoint_type"] = entrypoint_type
        generated_row.update(_summary_metadata(item, config))
        summary["generated"].append(generated_row)

    unmatched = [
        _runtime_result(discovery, "rejected", "runtime_discovery_unmatched_config")
        for index, discovery in enumerate(discoveries)
        if index not in consumed_discoveries
    ]
    if unmatched:
        summary["runtime_param_discoveries"] = unmatched

    if summary_path is not None:
        Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
        Path(summary_path).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        param_summary_path = Path(summary_path).with_name("generated_param_summary.json")
        param_summary = build_generated_param_summary(
            seed_report,
            summary,
            output_config_dir=output_dir,
        )
        if unmatched:
            param_summary["runtime_param_discoveries"] = unmatched
        param_summary_path.write_text(json.dumps(param_summary, indent=2), encoding="utf-8")

    return summary


def merge_runtime_param_discoveries(
    config: dict[str, Any],
    seed_item: Mapping[str, Any],
    discoveries: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Merge validated helper observations without changing the PHUZZ schema."""
    results: list[dict[str, Any]] = []
    for discovery in discoveries:
        reason = _runtime_discovery_rejection(discovery, seed_item)
        if reason:
            results.append(_runtime_result(discovery, "rejected", reason))
            continue

        path = _normalized_parameter_path(discovery["parameter_path"])
        location, inferred = _runtime_config_location(config, seed_item, discovery["http_source"], path)
        if path in _config_fixed_paths(config):
            results.append(_runtime_result(discovery, "ignored_fixed", "runtime_discovery_ignored_fixed_parameter", location))
            continue
        section = config.setdefault(f"{location}_params", {"data": [], "fixed": [], "fuzz": [], "weight": 1})
        existing = _section_parameter_paths(section)
        fixed_paths = _section_fixed_paths(section)
        if path in fixed_paths:
            results.append(_runtime_result(discovery, "ignored_fixed", "runtime_discovery_ignored_fixed_parameter", location))
            continue
        if path in existing:
            prior = next(
                (
                    row
                    for row in results
                    if row.get("config_location") == location
                    and normalized_parameter_path(row.get("parameter_path")) == path
                    and row.get("merge_action") in {"added", "matched_existing"}
                ),
                None,
            )
            if prior is not None:
                prior["observation_count"] = int(prior.get("observation_count", 1)) + 1
            else:
                results.append(_runtime_result(discovery, "ignored_duplicate", None, location, inferred=inferred))
            continue
        if any(existing_path[: len(path)] == path for existing_path in existing):
            prior = next(
                (
                    row
                    for row in results
                    if row.get("config_location") == location
                    and normalized_parameter_path(row.get("parameter_path")) == path
                    and row.get("merge_action") == "matched_existing"
                ),
                None,
            )
            if prior is not None:
                prior["observation_count"] = int(prior.get("observation_count", 1)) + 1
            else:
                results.append(_runtime_result(discovery, "matched_existing", None, location, inferred=inferred))
            continue

        name = _parameter_name_from_path(path)
        section["data"].append({"name": name, "value": "fuzz"})
        section["fuzz"].append(_selector_for_generated_param(name))
        results.append(_runtime_result(discovery, "added", None, location, inferred=inferred))

    if results:
        metadata = config.setdefault("metadata", {})
        metadata["runtime_param_provenance"] = results
        fuzzing_ready = bool(_config_fuzz_params(config))
        metadata["fuzzing_ready"] = fuzzing_ready
        config["config_type"] = "fuzzing_ready" if fuzzing_ready else "replay_only"
    return results


def normalized_parameter_path(value: Any) -> tuple[str, ...] | None:
    if isinstance(value, str):
        parts = [part for part in re.findall(r"[^\[\]]+", value) if part]
    elif isinstance(value, list) and all(isinstance(part, str) and part for part in value):
        parts = value
    else:
        return None
    return tuple(parts) or None


def _normalized_parameter_path(value: Any) -> tuple[str, ...]:
    path = normalized_parameter_path(value)
    if path is None:
        raise ValueError("invalid parameter path")
    return path


def _runtime_discovery_matches_seed(discovery: Mapping[str, Any], seed_item: Mapping[str, Any]) -> bool:
    return (
        isinstance(discovery, Mapping)
        and str(discovery.get("callback_id", "")) == str(seed_item.get("callback_id", ""))
        and str(discovery.get("entrypoint_name", "")) == str(seed_item.get("hook_name", ""))
    )


def _runtime_discovery_rejection(discovery: Mapping[str, Any], seed_item: Mapping[str, Any]) -> str | None:
    if not isinstance(discovery, Mapping):
        return "runtime_discovery_malformed"
    if discovery.get("schema_version") != "hookphuzz-runtime-param-v1":
        return "runtime_discovery_unsupported_schema"
    name = discovery.get("parameter_name")
    path = normalized_parameter_path(discovery.get("parameter_path"))
    if not isinstance(name, str) or not name.strip() or path is None:
        return "runtime_discovery_malformed_parameter"
    if str(discovery.get("callback_id", "")) != str(seed_item.get("callback_id", "")):
        return "runtime_discovery_callback_mismatch"
    if str(discovery.get("entrypoint_name", "")) != str(seed_item.get("hook_name", "")):
        return "runtime_discovery_entrypoint_mismatch"
    hook_name = str(seed_item.get("hook_name", ""))
    if hook_name.startswith("wp_ajax_"):
        expected_type = "wp_ajax"
    elif hook_name.startswith("rest_route:") or seed_item.get("entrypoint_type") == "rest_route":
        expected_type = "rest_route"
    else:
        expected_type = ""
    if not expected_type or discovery.get("entrypoint_type") != expected_type:
        return "runtime_discovery_entrypoint_type_mismatch"
    if str(discovery.get("http_source", "")).upper() not in {"GET", "POST", "REQUEST", "COOKIE", "FILTER_INPUT_GET", "FILTER_INPUT_POST", "REST_GET_PARAM"}:
        return "runtime_discovery_unsupported_source"
    if not isinstance(discovery.get("reader_function"), str) or not discovery["reader_function"].strip():
        return "runtime_discovery_missing_reader_function"
    if discovery.get("confidence") != "high" or discovery.get("discovery_mode") != "dynamic-helper":
        return "runtime_discovery_untrusted"
    if _is_trace_only_parameter(name):
        return "runtime_discovery_trace_or_debug_parameter"
    return None


def _is_trace_only_parameter(name: str) -> bool:
    return name.lower() in {"trace", "debug", "request_id", "coverage_id"} or name.lower().startswith("hookphuzz_")


def _runtime_config_location(
    config: Mapping[str, Any], seed_item: Mapping[str, Any], source: str, path: tuple[str, ...]
) -> tuple[str, bool]:
    source = source.upper()
    if source in {"POST", "FILTER_INPUT_POST"}:
        return "body", False
    if source in {"GET", "FILTER_INPUT_GET"}:
        return "query", False
    if source == "REST_GET_PARAM":
        if "body_params" in config and "query_params" not in config:
            return "body", False
        return "query", False
    if source == "COOKIE":
        return "cookies", False
    for location in ("body", "query"):
        if any(existing[:1] == path[:1] for existing in _section_parameter_paths(config.get(f"{location}_params", {}))):
            return location, False
    is_ajax = str(seed_item.get("hook_name", "")).startswith("wp_ajax_")
    return ("body" if is_ajax else "query"), True


def _section_parameter_paths(section: Any) -> set[tuple[str, ...]]:
    if not isinstance(section, Mapping):
        return set()
    values = section.get("data", [])
    if not isinstance(values, list):
        return set()
    return {
        path
        for item in values
        if isinstance(item, Mapping)
        for path in [normalized_parameter_path(item.get("name"))]
        if path is not None
    }


def _section_fixed_paths(section: Any) -> set[tuple[str, ...]]:
    if not isinstance(section, Mapping):
        return set()
    fixed = section.get("fixed", [])
    values = section.get("data", [])
    if not isinstance(fixed, list) or not isinstance(values, list):
        return set()
    fixed_selectors = {str(value) for value in fixed}
    return {
        path
        for item in values
        if isinstance(item, Mapping)
        and _selector_for_generated_param(str(item.get("name", ""))) in fixed_selectors
        for path in [normalized_parameter_path(item.get("name"))]
        if path is not None
    }


def _config_fixed_paths(config: Mapping[str, Any]) -> set[tuple[str, ...]]:
    return set().union(*(_section_fixed_paths(config.get(f"{location}_params", {})) for location in ("body", "query", "cookies")))


def _parameter_name_from_path(path: tuple[str, ...]) -> str:
    return path[0] + "".join(f"[{part}]" for part in path[1:])


def _runtime_result(
    discovery: Mapping[str, Any],
    merge_action: str,
    reason: str | None = None,
    config_location: str | None = None,
    *,
    inferred: bool = False,
) -> dict[str, Any]:
    row = {
        "parameter": discovery.get("parameter_name") if isinstance(discovery, Mapping) else None,
        "parameter_path": discovery.get("parameter_path") if isinstance(discovery, Mapping) else None,
        "source": discovery.get("http_source") if isinstance(discovery, Mapping) else None,
        "config_location": config_location,
        "origin": "runtime_helper",
        "reader_function": discovery.get("reader_function") if isinstance(discovery, Mapping) else None,
        "callback_id": discovery.get("callback_id") if isinstance(discovery, Mapping) else None,
        "entrypoint_name": discovery.get("entrypoint_name") if isinstance(discovery, Mapping) else None,
        "confidence": discovery.get("confidence") if isinstance(discovery, Mapping) else None,
        "merge_action": merge_action,
        "observation_count": int(discovery.get("observation_count", 1)) if isinstance(discovery, Mapping) else 1,
    }
    if reason:
        row["reason"] = reason
    if inferred:
        row["placement_inferred_from_entrypoint_template"] = True
    return row


def build_generated_param_summary(
    seed_report: Mapping[str, Any],
    config_summary: Mapping[str, Any],
    *,
    output_config_dir: str | Path,
) -> dict[str, Any]:
    output_dir = Path(output_config_dir)
    suggestions = [item for item in seed_report.get("suggested_seeds", []) if isinstance(item, Mapping)]
    by_key = {(str(item.get("hook_name", "")), str(item.get("callback_id", ""))): item for item in suggestions}

    rows: list[dict[str, Any]] = []
    for generated in config_summary.get("generated", []):
        if not isinstance(generated, Mapping):
            continue
        hook_name = str(generated.get("hook_name", ""))
        callback_id = str(generated.get("callback_id", ""))
        seed_item = by_key.get((hook_name, callback_id), {})
        config_path = output_dir / f"{_build_file_slug(seed_item)}.json"
        config = _read_json_object(config_path)
        fuzz_params = _config_fuzz_params(config)
        source_found = _callback_source_found(seed_item)
        status = "fuzzing_ready" if fuzz_params else "entrypoint_only"
        if not source_found:
            status = "manual_analysis"
        rows.append(
            {
                "hook_name": hook_name,
                "callback_repr": _callback_repr(seed_item, callback_id),
                "config_path": str(config_path),
                "endpoint_type": _endpoint_type(hook_name, seed_item, config),
                "entrypoint_type": config.get("entrypoint_type") or seed_item.get("entrypoint_type"),
                "callback_start_line": _callback_start_line(seed_item),
                "auth_mode": _config_metadata_value(config, "auth_mode"),
                "generated_reason": _config_metadata_value(config, "generated_reason"),
                "fuzzing_ready": bool(_config_metadata_value(config, "fuzzing_ready")),
                "setup_required": bool(_config_metadata_value(config, "setup_required")),
                "manual_analysis": bool(_config_metadata_value(config, "manual_analysis")),
                "missing_requirements": _config_metadata_value(config, "missing_requirements") or [],
                "callback_source_file": _callback_source_file(seed_item),
                "callback_source_found": source_found,
                "extracted_params": fuzz_params,
                "param_sources": _param_sources(seed_item, fuzz_params, source_found=source_found),
                "runtime_param_provenance": _config_metadata_value(config, "runtime_param_provenance") or [],
                "has_fuzz_params": bool(fuzz_params),
                "status": status,
            }
        )

    return {
        "summary": {
            "total": len(rows),
            "fuzzing_ready": len([item for item in rows if item["status"] == "fuzzing_ready"]),
            "entrypoint_only": len([item for item in rows if item["status"] == "entrypoint_only"]),
            "manual_analysis": len([item for item in rows if item["status"] == "manual_analysis"]),
        },
        "configs": rows,
    }


def _build_param_section(
    values: Mapping[str, Any],
    *,
    fixed_params: set[str],
    fuzzable_params: set[str],
) -> dict[str, Any]:
    fixed: list[str] = []
    fuzz: list[str] = []
    data: list[dict[str, str]] = []

    for name, value in values.items():
        param_name = str(name)
        if param_name in fuzzable_params and param_name not in fixed_params:
            data.append({"name": param_name, "value": "fuzz"})
            fuzz.append(_selector_for_generated_param(param_name))
        else:
            data.append({"name": param_name, "value": str(value)})
            fixed.append(_selector_for_generated_param(param_name))

    return {"data": data, "fixed": fixed, "fuzz": fuzz, "weight": 1}


def _selector_for_generated_param(param_name: str) -> str:
    if param_name == ".*":
        return param_name
    return re.escape(param_name)


def _build_file_slug(seed_item: Mapping[str, Any]) -> str:
    hook_name = str(seed_item.get("hook_name", "hook")).strip() or "hook"
    callback_id = str(seed_item.get("callback_id", "callback")).strip() or "callback"
    return f"{_safe_slug(hook_name)}-{_safe_slug(callback_id)}"


def _build_config_slug(output_dir: Path, file_slug: str) -> str:
    parts = list(output_dir.parts)
    lowered = [part.lower() for part in parts]
    if "configs" in lowered:
        configs_index = len(lowered) - 1 - lowered[::-1].index("configs")
        slug_parts = parts[configs_index + 1 :] + [file_slug]
        return "/".join(slug_parts)
    return file_slug


def _join_target(target_base: str, path: str) -> str:
    return target_base.rstrip("/") + "/" + path.lstrip("/")


def _seed_methods(seed: Mapping[str, Any]) -> list[str]:
    raw_methods = seed.get("methods", seed.get("method", ""))
    if isinstance(raw_methods, list):
        items = raw_methods
    else:
        items = [raw_methods]

    methods: list[str] = []
    for item in items:
        for part in str(item or "").replace("|", ",").split(","):
            method = part.strip().upper()
            if method and method not in methods:
                methods.append(method)
    return methods


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return slug.strip("._-") or "item"


def _string_set(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(item) for item in value if str(item)}


def _entrypoint_type_for_seed(seed_item: Mapping[str, Any], seed: Mapping[str, Any], path: str) -> str:
    explicit = str(seed.get('entrypoint_type') or seed_item.get('entrypoint_type') or '').strip()
    if explicit:
        return explicit
    hook_name = str(seed_item.get('hook_name', '')).strip()
    if hook_name.startswith('wp_ajax_nopriv_'):
        return 'ajax_unauthenticated'
    if hook_name.startswith('wp_ajax_'):
        return 'ajax_authenticated'
    if hook_name.startswith('admin_post_nopriv_'):
        return 'admin_post_unauthenticated'
    if hook_name.startswith('admin_post_'):
        return 'admin_post_authenticated'
    if hook_name.startswith('login_form_'):
        return 'login_form'
    if hook_name in {'heartbeat_received', 'heartbeat_nopriv_received'}:
        return 'heartbeat'
    if '/wp-json/' in path:
        return 'rest_route'
    return ''


def _metadata_for_seed_item(
    seed_item: Mapping[str, Any],
    seed: Mapping[str, Any],
    *,
    entrypoint_type: str,
    fuzzing_ready: bool,
    discovered_file_params: list[Any],
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        'entrypoint_type': entrypoint_type,
        'hook_name': str(seed_item.get('hook_name', '')),
        'callback_repr': _callback_repr(seed_item, str(seed_item.get('callback_id', ''))),
        'callback_source_file': _callback_source_file(seed_item),
        'callback_start_line': _callback_start_line(seed_item),
        'auth_mode': str(seed.get('auth_mode') or ''),
        'generated_reason': str(seed_item.get('generated_reason') or seed_item.get('generation_status') or ''),
        'fuzzing_ready': fuzzing_ready,
        'setup_required': bool(seed_item.get('setup_required', False)),
        'manual_analysis': bool(seed_item.get('manual_analysis', False)),
    }
    route = seed_item.get('route') or seed_item.get('rest_route')
    if route:
        metadata['route'] = route
    if discovered_file_params:
        metadata['discovered_file_params'] = discovered_file_params
    missing = _missing_requirements(seed_item, fuzzing_ready=fuzzing_ready)
    if missing:
        metadata['missing_requirements'] = missing
    return metadata


def _summary_metadata(seed_item: Mapping[str, Any], config: Mapping[str, Any]) -> dict[str, Any]:
    metadata = config.get('metadata')
    if not isinstance(metadata, Mapping):
        metadata = {}
    keys = (
        'entrypoint_type',
        'hook_name',
        'route',
        'callback_repr',
        'callback_source_file',
        'callback_start_line',
        'auth_mode',
        'generated_reason',
        'fuzzing_ready',
        'setup_required',
        'manual_analysis',
        'missing_requirements',
    )
    return {key: metadata[key] for key in keys if key in metadata}


def _skipped_row(seed_item: Mapping[str, Any], hook_name: str, callback_id: str, reason: str) -> dict[str, Any]:
    row: dict[str, Any] = {
        'hook_name': hook_name,
        'callback_id': callback_id,
        'reason': reason,
        'callback_repr': _callback_repr(seed_item, callback_id),
        'callback_source_file': _callback_source_file(seed_item),
        'callback_start_line': _callback_start_line(seed_item),
        'auth_mode': str(seed_item.get('auth_mode') or ''),
        'generated_reason': str(seed_item.get('generated_reason') or seed_item.get('generation_status') or reason),
        'fuzzing_ready': False,
        'setup_required': bool(seed_item.get('setup_required', False)),
        'manual_analysis': bool(seed_item.get('manual_analysis', reason == 'missing_seed')),
        'missing_requirements': _missing_requirements(seed_item, fuzzing_ready=False),
    }
    entrypoint_type = str(seed_item.get('entrypoint_type') or '').strip()
    if entrypoint_type:
        row['entrypoint_type'] = entrypoint_type
    route = seed_item.get('route') or seed_item.get('rest_route')
    if route:
        row['route'] = route
    return row


def _callback_start_line(seed_item: Mapping[str, Any]) -> int | None:
    for key in ('callback_start_line', 'start_line', 'source_line'):
        value = seed_item.get(key)
        if value not in (None, ''):
            return int(value)
    return None


def _missing_requirements(seed_item: Mapping[str, Any], *, fuzzing_ready: bool) -> list[str]:
    if fuzzing_ready:
        return []
    existing = seed_item.get('missing_requirements')
    if isinstance(existing, list):
        return [str(item) for item in existing if str(item)]
    return ['fuzzable_params']

def _read_json_object(path: Path) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, Mapping) else {}


def _config_fuzz_params(config: Mapping[str, Any]) -> list[str]:
    params: list[str] = []
    for key in ("body_params", "query_params", "cookies"):
        section = config.get(key)
        if not isinstance(section, Mapping):
            continue
        for name in section.get("fuzz", []):
            param_name = str(name)
            if param_name and param_name not in params:
                params.append(param_name)
    return params


def _config_metadata_value(config: Mapping[str, Any], key: str) -> Any:
    metadata = config.get('metadata')
    if isinstance(metadata, Mapping):
        return metadata.get(key)
    return None

def _callback_repr(seed_item: Mapping[str, Any], callback_id: str) -> str:
    for key in ("callback_repr", "callback_name", "callback_raw"):
        value = str(seed_item.get(key, "")).strip()
        if value:
            return value
    return callback_id


def _callback_source_file(seed_item: Mapping[str, Any]) -> str:
    resolution = seed_item.get("source_resolution")
    if isinstance(resolution, Mapping):
        value = str(resolution.get("source_file") or resolution.get("resolved_source_file") or "").strip()
        if value:
            return value
    return str(seed_item.get("source_file") or "").strip()


def _callback_source_found(seed_item: Mapping[str, Any]) -> bool:
    resolution = seed_item.get("source_resolution")
    if not isinstance(resolution, Mapping):
        return False
    status = str(resolution.get("status", "")).strip()
    return bool(status and status != "unresolved" and resolution.get("resolved_source_file"))


def _endpoint_type(hook_name: str, seed_item: Mapping[str, Any], config: Mapping[str, Any]) -> str:
    entrypoint_type = str(config.get("entrypoint_type") or seed_item.get("entrypoint_type") or "").strip()
    target = str(config.get("target", ""))
    if hook_name.startswith("rest_route:") or entrypoint_type == "rest_route" or "/wp-json/" in target:
        return "rest"
    if hook_name.startswith(("wp_ajax_", "wp_ajax_nopriv_")) or "admin-ajax.php" in target:
        return "ajax"
    if hook_name.startswith(("admin_post_", "admin_post_nopriv_")) or "admin-post.php" in target:
        return "admin_post"
    return "unknown"


def _param_sources(seed_item: Mapping[str, Any], params: list[str], *, source_found: bool) -> list[str]:
    seed = seed_item.get("seed")
    input_params = seed.get("input_params", []) if isinstance(seed, Mapping) else []
    source_by_name: dict[str, str] = {}
    if isinstance(input_params, list):
        for item in input_params:
            if not isinstance(item, Mapping):
                continue
            name = str(item.get("name", "")).strip()
            if name and name not in source_by_name:
                source_by_name[name] = _param_source_label(item)

    labels: list[str] = []
    for name in params:
        label = source_by_name.get(name) or ("default" if source_found else "manual")
        if label not in labels:
            labels.append(label)
    return labels


def _param_source_label(item: Mapping[str, Any]) -> str:
    confidence = str(item.get("confidence", ""))
    if confidence.startswith("shallow_helper"):
        return "helper"
    source = str(item.get("source", "")).upper()
    return {
        "GET": "$_GET",
        "POST": "$_POST",
        "REQUEST": "$_REQUEST",
        "COOKIE": "$_COOKIE",
    }.get(source, "manual")






