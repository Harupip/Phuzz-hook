from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..rest_routes import materialize_rest_route
from .config_exporter import export_seed_configs
from .static_generator import StaticSeedGenerator
from .zend_runtime.candidate_generator import ZendRuntimeSeedGenerator


LOCATION_CANDIDATES = ["query", "form", "json"]
SUPPORTED_SCHEMA_TYPES = {"string", "integer", "number", "boolean", None}


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
        (output_path / "suggested_seeds.json").write_text(json.dumps(seed_report, indent=2), encoding="utf-8")

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
    for item in seed_report.get("suggested_seeds", []):
        if not isinstance(item, dict) or item.get("entrypoint_type") != "rest_route":
            continue
        seed = item.get("seed")
        if not isinstance(seed, dict):
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
        if policy["block_reasons"]:
            seed["export_allowed"] = False
            seed["replay_allowed"] = False
            seed["block_reason"] = policy["block_reasons"][0]
            item["generation_status"] = policy["block_reasons"][0]
            item["generated_reason"] = policy["block_reasons"][0]
            item["fuzzing_ready"] = False
            item["missing_requirements"] = list(policy["block_reasons"])


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
            parameters.append(
                {
                    "name": name,
                    "location": source["location"],
                    "location_candidates": [],
                    "source": source["source"],
                    "schema_type": schema_type,
                    "materialized": False,
                }
            )
        else:
            parameters.append(
                {
                    "name": name,
                    "location": "unknown",
                    "location_candidates": list(LOCATION_CANDIDATES),
                    "source": "schema_only",
                    "schema_type": schema_type,
                    "materialized": False,
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


def _evidence_by_name(seed: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    output: dict[str, dict[str, str]] = {}
    input_params = seed.get("input_params")
    if not isinstance(input_params, Sequence) or isinstance(input_params, (str, bytes, bytearray)):
        return output
    for item in input_params:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "").strip()
        source = str(item.get("source") or "").strip().upper()
        location = _location_for_source(source)
        if name and location and name not in output:
            output[name] = {"source": source, "location": location}
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
        if isinstance(row, Mapping)
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
