from __future__ import annotations

import json
import re
from collections.abc import Mapping
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

    method_status = seed.get("method_status")
    if method_status == "ambiguous" or seed.get("method_confidence") == "ambiguous":
        raise SeedConfigSkip("ambiguous_http_method")
    if seed.get("export_allowed") is False or (method_status and method_status != "resolved"):
        raise SeedConfigSkip(str(seed.get("block_reason") or "blocked_http_method"))

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
    write_param_summary: bool = True,
) -> dict[str, list[dict[str, str]]]:
    output_dir = Path(output_config_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    summary: dict[str, list[dict[str, str]]] = {"generated": [], "skipped": []}
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

        config_path = output_dir / f"{file_slug}.json"
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        generated_row = {
            "config_slug": _build_config_slug(output_dir, file_slug),
            "hook_name": hook_name,
            "callback_id": callback_id,
        }
        entrypoint_type = str(config.get("entrypoint_type", "")).strip()
        if entrypoint_type:
            generated_row["entrypoint_type"] = entrypoint_type
        generated_row.update(_summary_metadata(item, config))
        summary["generated"].append(generated_row)

    if summary_path is not None:
        Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
        Path(summary_path).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        if write_param_summary:
            param_summary_path = Path(summary_path).with_name("generated_param_summary.json")
            param_summary = build_generated_param_summary(
                seed_report,
                summary,
                output_config_dir=output_dir,
            )
            param_summary_path.write_text(json.dumps(param_summary, indent=2), encoding="utf-8")

    return summary


def build_generated_param_summary(
    seed_report: Mapping[str, Any],
    config_summary: Mapping[str, Any],
    *,
    output_config_dir: str | Path,
) -> dict[str, Any]:
    output_dir = Path(output_config_dir)
    suggestions = [item for item in seed_report.get("suggested_seeds", []) if isinstance(item, Mapping)]
    by_key = {
        (
            str(item.get("hook_name", "")),
            str(item.get("callback_id", "")),
            str((item.get("seed") or {}).get("seed_variant_id", ""))
            if isinstance(item.get("seed"), Mapping)
            else "",
        ): item
        for item in suggestions
    }

    rows: list[dict[str, Any]] = []
    for generated in config_summary.get("generated", []):
        if not isinstance(generated, Mapping):
            continue
        hook_name = str(generated.get("hook_name", ""))
        callback_id = str(generated.get("callback_id", ""))
        variant = str(generated.get("seed_variant_id", ""))
        seed_item = by_key.get((hook_name, callback_id, variant), {})
        config_slug = str(generated.get("config_slug") or "")
        config_name = Path(config_slug.replace("\\", "/")).name
        config_path = output_dir / f"{config_name}.json"
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
                "has_fuzz_params": bool(fuzz_params),
                "status": status,
                "resolved_method": _config_metadata_value(config, "resolved_method"),
                "candidate_methods": _config_metadata_value(config, "candidate_methods") or [],
                "method_confidence": _config_metadata_value(config, "method_confidence"),
                "observed_request_method": _config_metadata_value(config, "observed_request_method"),
                "route_declared_methods": _config_metadata_value(config, "route_declared_methods") or [],
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
    data: list[dict[str, Any]] = []

    for name, value in values.items():
        param_name = str(name)
        if param_name in fuzzable_params and param_name not in fixed_params:
            data.append({"name": param_name, "value": "fuzz"})
            fuzz.append(_selector_for_generated_param(param_name))
        else:
            # JSON request preparation relies on native booleans and numbers.
            data.append({"name": param_name, "value": value})
            fixed.append(_selector_for_generated_param(param_name))

    return {"data": data, "fixed": fixed, "fuzz": fuzz, "weight": 1}


def _selector_for_generated_param(param_name: str) -> str:
    if param_name == ".*":
        return param_name
    return re.escape(param_name)


def _build_file_slug(seed_item: Mapping[str, Any]) -> str:
    hook_name = str(seed_item.get("hook_name", "hook")).strip() or "hook"
    callback_id = str(seed_item.get("callback_id", "callback")).strip() or "callback"
    seed = seed_item.get("seed")
    variant = str(seed.get("seed_variant_id", "")) if isinstance(seed, Mapping) else ""
    suffix = f"-{_safe_slug(variant)}" if variant else ""
    return f"{_safe_slug(hook_name)}-{_safe_slug(callback_id)}{suffix}"


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
        'method_source': str(seed.get('method_source') or 'legacy_artifact'),
        'method_confidence': str(seed.get('method_confidence') or 'low'),
        'method_evidence': seed.get('method_evidence'),
        'resolved_method': seed.get('resolved_method', seed.get('method')),
        'candidate_methods': list(seed.get('candidate_methods') or _seed_methods(seed)),
        'method_status': str(seed.get('method_status') or 'resolved'),
        'observed_request_method': seed.get('observed_request_method'),
        'route_declared_methods': list(seed.get('route_declared_methods') or []),
        'seed_variant_id': str(seed.get('seed_variant_id') or ''),
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
        'method_source',
        'method_confidence',
        'method_evidence',
        'resolved_method',
        'candidate_methods',
        'method_status',
        'observed_request_method',
        'route_declared_methods',
        'seed_variant_id',
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
    seed = seed_item.get("seed")
    if isinstance(seed, Mapping):
        for key in (
            "resolved_method",
            "candidate_methods",
            "method_status",
            "method_source",
            "method_confidence",
            "method_evidence",
            "observed_request_method",
            "route_declared_methods",
        ):
            if key in seed:
                row[key] = seed[key]
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
    for key in ("body_params", "query_params"):
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
