from __future__ import annotations

import json
import re
from copy import deepcopy
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..rest_routes import materialize_rest_route
from .config_exporter import export_seed_configs
from .static_generator import StaticSeedGenerator
from .zend_runtime.candidate_generator import ZendRuntimeSeedGenerator


LOCATION_CANDIDATES = ["query", "form", "json"]
SUPPORTED_SCHEMA_TYPES = {"string", "integer", "number", "boolean", None}
PROBE_ONLY_CONTENT_TYPES = {
    "form": "application/x-www-form-urlencoded",
    "json": "application/json",
}
PROBE_ONLY_SECURITY_NAME = re.compile(r"(?:nonce|token|secret|password|cookie|authorization|auth)", re.IGNORECASE)


def run_entrypoint_pipeline(
    coverage_payload: Mapping[str, Any],
    *,
    plugin_slug: str,
    output_dir: str | Path,
    output_config_dir: str | Path | None = None,
    minimal_artifacts: bool = False,
    target_base: str = "http://web",
    container_source_root: str | Path | None = None,
    host_source_root: str | Path | None = None,
    source_root: str | Path | None = None,
    unresolved_source_reason: str | None = None,
    runtime_parameters_only: bool = False,
) -> dict[str, Any]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    generator = (
        ZendRuntimeSeedGenerator()
        if runtime_parameters_only
        else StaticSeedGenerator(
            container_source_root=container_source_root,
            host_source_root=host_source_root,
            source_root=source_root,
            unresolved_source_reason=unresolved_source_reason,
        )
    )
    gap_report, seed_report = generator.build_reports(dict(coverage_payload))
    registered = _registered_callbacks(coverage_payload)
    _apply_rest_parameter_policy(seed_report, registered)

    if minimal_artifacts:
        (output_path / "runtime_coverage_snapshot.json").write_text(
            json.dumps(coverage_payload, indent=2),
            encoding="utf-8",
        )
    else:
        (output_path / "hook_gap_report.json").write_text(json.dumps(gap_report, indent=2), encoding="utf-8")
        (output_path / "suggested_seeds.json").write_text(
            json.dumps(_redacted_probe_seed_report(seed_report), indent=2),
            encoding="utf-8",
        )

    config_dir = Path(output_config_dir) if output_config_dir is not None else output_path / "configs"
    config_summary_path = output_path / "generated_config_summary.json"
    config_summary = export_seed_configs(
        seed_report,
        output_config_dir=config_dir,
        summary_path=config_summary_path,
        target_base=target_base,
        write_param_summary=not minimal_artifacts,
    )
    pipeline_summary = _pipeline_summary(
        seed_report,
        config_summary,
        plugin_slug=plugin_slug,
        output_config_dir=config_dir,
    )
    (output_path / "entrypoint_pipeline_summary.json").write_text(
        json.dumps(pipeline_summary, indent=2),
        encoding="utf-8",
    )
    return {
        "gap_report": gap_report,
        "seed_report": seed_report,
        "config_summary": config_summary,
        "pipeline_summary": pipeline_summary,
    }


def _registered_callbacks(coverage_payload: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    data = coverage_payload.get("data")
    registered = data.get("registered_callbacks") if isinstance(data, Mapping) else None
    if isinstance(registered, list):
        return {
            str(item.get("callback_id") or index): item
            for index, item in enumerate(registered)
            if isinstance(item, Mapping)
        }
    if not isinstance(registered, Mapping):
        return {}
    return {str(key): value for key, value in registered.items() if isinstance(value, Mapping)}


def _apply_rest_parameter_policy(
    seed_report: dict[str, Any],
    registered: Mapping[str, Mapping[str, Any]],
) -> None:
    probe_variants: list[dict[str, Any]] = []
    for item in list(seed_report.get("suggested_seeds", [])):
        if not isinstance(item, dict) or item.get("entrypoint_type") != "rest_route":
            continue
        seed = item.get("seed")
        if not isinstance(seed, dict):
            continue
        if seed.get("probe_variant"):
            continue
        callback_id = str(item.get("callback_id", ""))
        metadata = registered.get(callback_id, {})
        schema = _schema_parameters(metadata)
        route = str(item.get("route") or metadata.get("route") or "")
        materialized = materialize_rest_route(route)
        _merge_explicit_input_evidence(seed, metadata)
        policy = _rest_parameter_policy(schema, seed, materialized)
        _apply_evidence_to_rest_seed(seed, schema, policy)
        item["rest_parameter_policy"] = policy
        item["permission_callback"] = metadata.get("permission_callback", item.get("permission_callback"))
        probe_variants.extend(_build_rest_probe_seed_items(item, policy))
        if policy["block_reasons"]:
            seed["export_allowed"] = False
            seed["replay_allowed"] = False
            seed["block_reason"] = policy["block_reasons"][0]
            item["generation_status"] = policy["block_reasons"][0]
            item["generated_reason"] = policy["block_reasons"][0]
            item["fuzzing_ready"] = False
            item["missing_requirements"] = list(policy["block_reasons"])
    if probe_variants:
        seed_report.setdefault("suggested_seeds", []).extend(probe_variants)


def _schema_parameters(metadata: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    merged: dict[str, Mapping[str, Any]] = {}
    for key in ("route_common_argument_definitions", "argument_definitions"):
        value = metadata.get(key)
        if isinstance(value, Mapping):
            for name, schema in value.items():
                merged[str(name)] = schema if isinstance(schema, Mapping) else {"unsupported_schema": schema}
    return merged


def _rest_parameter_policy(
    schema: Mapping[str, Mapping[str, Any]],
    seed: Mapping[str, Any],
    materialized: Mapping[str, Any],
) -> dict[str, Any]:
    path_names = set((materialized.get("substitutions") or {}).keys()) if isinstance(materialized.get("substitutions"), Mapping) else set()
    evidence = _evidence_by_name(seed)
    parameters: list[dict[str, Any]] = []
    block_reasons: list[str] = []
    if materialized.get("route_materialization_status") == "unsupported":
        block_reasons.append(str(materialized.get("block_reason") or "unsupported_route_materialization"))

    for name, param_schema in sorted(schema.items()):
        schema_type = param_schema.get("type")
        if schema_type not in SUPPORTED_SCHEMA_TYPES or "unsupported_schema" in param_schema:
            block_reasons.append("unsupported_rest_schema")
        if name in path_names:
            parameters.append(
                {
                    "name": name,
                    "location": "path",
                    "location_candidates": [],
                    "source": "route_regex",
                    "schema_type": schema_type,
                    "materialized": True,
                }
            )
            continue
        source = evidence.get(name)
        if source:
            if source.get("location") == "unknown":
                probe_specs = _probe_variants_for_unresolved_param(
                    seed,
                    name=name,
                    schema_type=schema_type,
                )
                parameters.append(
                    {
                        "name": name,
                        "location": "unknown",
                        "location_candidates": list(LOCATION_CANDIDATES),
                        "source": source["source"],
                        "schema_type": schema_type,
                        "materialized": False,
                        "evidence_kind": source.get("evidence_kind"),
                        "probe_variants": probe_specs,
                    }
                )
                block_reasons.append("rest_schema_parameter_location_unknown")
                continue
            parameters.append(
                {
                    "name": name,
                    "location": source["location"],
                    "location_candidates": [],
                    "source": source["source"],
                    "schema_type": schema_type,
                    "materialized": False,
                    "evidence_kind": source.get("evidence_kind"),
                }
            )
        else:
            probe_specs = _probe_variants_for_unresolved_param(
                seed,
                name=name,
                schema_type=schema_type,
            )
            parameters.append(
                {
                    "name": name,
                    "location": "unknown",
                    "location_candidates": list(LOCATION_CANDIDATES),
                    "source": "schema_only",
                    "schema_type": schema_type,
                    "materialized": False,
                    "evidence_kind": None,
                    "probe_variants": probe_specs,
                }
            )
            block_reasons.append("rest_schema_parameter_location_unknown")

    return {"parameters": parameters, "block_reasons": _dedupe(block_reasons)}


def _merge_explicit_input_evidence(seed: dict[str, Any], metadata: Mapping[str, Any]) -> None:
    explicit = metadata.get("input_params")
    if not isinstance(explicit, Sequence) or isinstance(explicit, (str, bytes, bytearray)):
        return
    input_params = seed.setdefault("input_params", [])
    if not isinstance(input_params, list):
        input_params = []
        seed["input_params"] = input_params
    seen = {(str(item.get("name")), str(item.get("source"))) for item in input_params if isinstance(item, Mapping)}
    for item in explicit:
        if not isinstance(item, Mapping):
            continue
        key = (str(item.get("name")), str(item.get("source")))
        if key[0] and key not in seen:
            input_params.append(dict(item))
            seen.add(key)


def _apply_evidence_to_rest_seed(
    seed: dict[str, Any],
    schema: Mapping[str, Mapping[str, Any]],
    policy: Mapping[str, Any],
) -> None:
    if policy.get("block_reasons"):
        return
    body = seed.setdefault("body", {})
    query = seed.setdefault("query_params", {})
    headers = seed.setdefault("headers", {})
    fuzzable = seed.setdefault("fuzzable_params", [])
    if not isinstance(body, dict) or not isinstance(query, dict) or not isinstance(headers, dict) or not isinstance(fuzzable, list):
        return

    for parameter in policy.get("parameters", []):
        if not isinstance(parameter, Mapping):
            continue
        name = str(parameter.get("name") or "")
        if not name or name not in schema or parameter.get("location") == "path":
            continue
        location = parameter.get("location")
        if location == "query":
            query.setdefault(name, "FUZZ")
        elif location in {"form", "json"}:
            body.setdefault(name, "FUZZ")
            if location == "json":
                headers.setdefault("Content-Type", "application/json")
        if name not in fuzzable:
            fuzzable.append(name)


def _evidence_by_name(seed: Mapping[str, Any]) -> dict[str, dict[str, str | None]]:
    output: dict[str, dict[str, str | None]] = {}
    input_params = seed.get("input_params")
    if not isinstance(input_params, Sequence) or isinstance(input_params, (str, bytes, bytearray)):
        return output
    for item in input_params:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "").strip()
        source = str(item.get("source") or "").strip().upper()
        location = _location_for_source(source)
        if not name or name in output:
            continue
        if location:
            output[name] = {
                "source": source,
                "location": location,
                "evidence_kind": str(item.get("evidence_kind") or ""),
            }
        elif source == "REST_ARRAY_ACCESS":
            output[name] = {
                "source": source,
                "location": "unknown",
                "evidence_kind": "rest_array_access_name_only",
            }
    return output


def _location_for_source(source: str) -> str | None:
    return {
        "GET": "query",
        "REST_GET_PARAM": "query",
        "POST": "form",
        "FORM": "form",
        "JSON": "json",
        "BODY_JSON": "json",
    }.get(source)


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


def _probe_variants_for_unresolved_param(
    seed: Mapping[str, Any],
    *,
    name: str,
    schema_type: Any,
) -> list[dict[str, Any]]:
    if PROBE_ONLY_SECURITY_NAME.search(name):
        return []
    methods = _seed_methods(seed)
    if methods != ["POST"]:
        return []
    schema_label = str(schema_type or "string")
    variants: list[dict[str, Any]] = []
    for location in ("form", "json"):
        variants.append(
            {
                "seed_variant_id": f"rest_probe_{location}_{_variant_safe_name(name)}",
                "location": location,
                "content_type": PROBE_ONLY_CONTENT_TYPES[location],
                "schema_type": schema_label,
                "candidate_value_redacted": True,
            }
        )
    return variants


def _typed_probe_value(schema_type: Any) -> Any:
    normalized = str(schema_type or "string").lower()
    if normalized in {"integer", "number"}:
        return 1
    if normalized == "boolean":
        return True
    return "probe"


def _variant_safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._-") or "param"


def _build_rest_probe_seed_items(seed_item: Mapping[str, Any], policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    seed = seed_item.get("seed")
    if not isinstance(seed, Mapping):
        return []
    probe_items: list[dict[str, Any]] = []
    for parameter in policy.get("parameters", []):
        if not isinstance(parameter, Mapping):
            continue
        name = str(parameter.get("name") or "")
        for probe in parameter.get("probe_variants", []):
            if not isinstance(probe, Mapping):
                continue
            probe_items.append(_clone_probe_seed_item(seed_item, seed, name=name, probe=probe))
    return probe_items


def _clone_probe_seed_item(
    seed_item: Mapping[str, Any],
    seed: Mapping[str, Any],
    *,
    name: str,
    probe: Mapping[str, Any],
) -> dict[str, Any]:
    item = deepcopy(dict(seed_item))
    probe_seed = deepcopy(dict(seed))
    location = str(probe.get("location") or "")
    content_type = str(probe.get("content_type") or "")
    candidate_value = _typed_probe_value(probe.get("schema_type"))
    body = {}
    query = {}
    headers = {}
    if location in {"form", "json"}:
        body[name] = candidate_value
        if location == "json" and content_type:
            headers["Content-Type"] = content_type
    elif location == "query":
        query[name] = candidate_value
    probe_seed["body"] = body
    probe_seed["query_params"] = query
    probe_seed["headers"] = headers
    probe_seed["fixed_params"] = [name]
    probe_seed["fuzzable_params"] = []
    probe_seed["input_params"] = []
    probe_seed["export_allowed"] = True
    probe_seed["replay_allowed"] = True
    probe_seed["block_reason"] = None
    probe_seed["probe_variant"] = True
    probe_seed["seed_variant_id"] = str(probe.get("seed_variant_id") or "")
    item["seed"] = probe_seed
    item["generation_status"] = "rest_schema_parameter_probe"
    item["generated_reason"] = "rest_schema_parameter_probe"
    item["fuzzing_ready"] = False
    item["missing_requirements"] = ["callback_attributed_runtime_bucket_evidence"]
    item["probe_request"] = {
        "parameter": name,
        "location": location,
        "content_type": content_type,
        "schema_type": str(probe.get("schema_type") or ""),
        "candidate_value_redacted": bool(probe.get("candidate_value_redacted")),
    }
    return item


def _redacted_probe_seed_report(seed_report: Mapping[str, Any]) -> dict[str, Any]:
    report = deepcopy(dict(seed_report))
    items = report.get("suggested_seeds")
    if not isinstance(items, list):
        return report
    redacted: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        row = deepcopy(dict(item))
        seed = row.get("seed")
        if isinstance(seed, dict) and seed.get("probe_variant"):
            seed["body"] = _redact_probe_mapping(seed.get("body"))
            seed["query_params"] = _redact_probe_mapping(seed.get("query_params"))
        redacted.append(row)
    report["suggested_seeds"] = redacted
    return report


def _redact_probe_mapping(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): "redacted" for key in value.keys()}
    return value


def _pipeline_summary(
    seed_report: Mapping[str, Any],
    config_summary: Mapping[str, Any],
    *,
    plugin_slug: str,
    output_config_dir: Path,
) -> dict[str, Any]:
    generated = {
        _summary_key(row): row
        for row in config_summary.get("generated", [])
        if isinstance(row, Mapping) and not bool(row.get("probe_variant"))
    }
    skipped = {
        _summary_key(row): row
        for row in config_summary.get("skipped", [])
        if isinstance(row, Mapping)
    }
    entrypoints = []
    for item in seed_report.get("suggested_seeds", []):
        if not isinstance(item, Mapping):
            continue
        if _is_probe_variant_item(item):
            continue
        key = _summary_key(item)
        generated_row = generated.get(key)
        skipped_row = skipped.get(key)
        seed = item.get("seed") if isinstance(item.get("seed"), Mapping) else {}
        config_path = _config_path(output_config_dir, str(generated_row.get("config_slug"))) if generated_row else None
        entrypoints.append(
            {
                "plugin_slug": plugin_slug,
                "entrypoint_type": item.get("entrypoint_type"),
                "hook_name": item.get("hook_name"),
                "route": item.get("route"),
                "action": (seed.get("body") or seed.get("query_params") or {}).get("action") if isinstance(seed, Mapping) else None,
                "callback_id": item.get("callback_id"),
                "callback_repr": item.get("callback_repr") or item.get("callback_name"),
                "method": seed.get("method") if isinstance(seed, Mapping) else None,
                "candidate_methods": seed.get("candidate_methods") if isinstance(seed, Mapping) else [],
                "permission_callback": item.get("permission_callback"),
                "auth_mode": seed.get("auth_mode") if isinstance(seed, Mapping) else item.get("auth_mode"),
                "parameters": _summary_parameters(item),
                "config_status": "generated" if generated_row else "skipped",
                "skip_reason": skipped_row.get("reason") if skipped_row else None,
                "config_slug": generated_row.get("config_slug") if generated_row else None,
                "config_path": str(config_path) if config_path else None,
            }
        )
    return {
        "schema_version": 1,
        "plugin_slug": plugin_slug,
        "summary": {
            "entrypoints": len(entrypoints),
            "registered": int(seed_report.get("summary", {}).get("suggested_entries", len(entrypoints)))
            + int(_covered_count(seed_report)),
            "direct_http_candidates": int(seed_report.get("summary", {}).get("direct_http_seed_candidates", 0)),
            "generated": len(generated),
            "skipped": len(skipped),
            "ambiguous_http_method": sum(
                1
                for row in skipped.values()
                if isinstance(row, Mapping) and row.get("reason") == "ambiguous_http_method"
            ),
        },
        "entrypoints": entrypoints,
    }


def _covered_count(seed_report: Mapping[str, Any]) -> int:
    metadata = seed_report.get("coverage_metadata")
    if not isinstance(metadata, Mapping):
        return 0
    registered = metadata.get("total_registered_callbacks")
    uncovered = metadata.get("total_uncovered_callbacks")
    if registered is None or uncovered is None:
        return 0
    try:
        return max(0, int(registered) - int(uncovered))
    except (TypeError, ValueError):
        return 0


def _summary_key(row: Mapping[str, Any]) -> tuple[str, str, str]:
    seed = row.get("seed")
    variant = row.get("seed_variant_id")
    if not variant and isinstance(seed, Mapping):
        variant = seed.get("seed_variant_id")
    return (
        str(row.get("hook_name") or ""),
        str(row.get("callback_id") or ""),
        str(variant or ""),
    )


def _is_probe_variant_item(item: Mapping[str, Any]) -> bool:
    seed = item.get("seed")
    return isinstance(seed, Mapping) and bool(seed.get("probe_variant"))


def _config_path(output_config_dir: Path, config_slug: str) -> Path:
    return output_config_dir / (Path(config_slug.replace("\\", "/")).name + ".json")


def _summary_parameters(item: Mapping[str, Any]) -> list[dict[str, Any]]:
    policy = item.get("rest_parameter_policy")
    if isinstance(policy, Mapping) and isinstance(policy.get("parameters"), list):
        return list(policy["parameters"])
    seed = item.get("seed")
    if not isinstance(seed, Mapping):
        return []
    return [
        {
            "name": param.get("name"),
            "location": _location_for_source(str(param.get("source") or "").upper()) or "unknown",
            "source": param.get("source"),
        }
        for param in seed.get("input_params", [])
        if isinstance(param, Mapping)
    ]


def _dedupe(values: Sequence[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        if value and value not in output:
            output.append(value)
    return output
