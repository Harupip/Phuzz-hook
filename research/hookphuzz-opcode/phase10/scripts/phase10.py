#!/usr/bin/env python3
"""Phase 10 evidence merge and PHUZZ-schema compatibility helpers."""
from __future__ import annotations

import json
import os
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


PHASE10_SCHEMA = 1
PHASE9_ARTIFACT_SCHEMA = 3


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temp = Path(handle.name)
    os.replace(temp, path)


def path_parts(value: Any) -> tuple[str, ...] | None:
    if isinstance(value, str):
        parts = [part for part in value.replace("]", "").split("[") if part]
    elif isinstance(value, list) and all(isinstance(part, (str, int)) for part in value):
        parts = [str(part) for part in value]
    else:
        return None
    return tuple(parts) or None


def path_name(parts: tuple[str, ...]) -> str:
    return parts[0] + "".join(f"[{part}]" for part in parts[1:])


def placement_for_source(source: str, *, request_placement: str | None = None) -> str | None:
    source = source.upper()
    if source in {"GET", "FILTER_INPUT_GET", "REST_GET_PARAM"}:
        return "query"
    if source in {"POST", "FILTER_INPUT_POST"}:
        return "body"
    if source == "COOKIE":
        return "cookie"
    if source == "REQUEST":
        return request_placement
    return None


def logical_key(row: dict[str, Any]) -> tuple[str, str, str, str, tuple[str, ...], str]:
    parts = path_parts(row.get("parameter_path") or row.get("path"))
    placement = str(row.get("placement") or row.get("http_placement") or "")
    fields = ("plugin", "entrypoint", "root_callback", "source")
    if not parts or not placement or any(not str(row.get(field, "")) for field in fields):
        raise ValueError("evidence is missing Phase 10 association fields")
    return tuple(str(row[field]) for field in fields) + (parts, placement)  # type: ignore[return-value]


def normalize_opcode(plugin: str, entrypoint: str, artifact: dict[str, Any], *, request_placement: str | None = None) -> list[dict[str, Any]]:
    if artifact.get("schema_version") != PHASE9_ARTIFACT_SCHEMA:
        raise ValueError("unsupported_phase9_artifact_schema")
    request_id = artifact.get("request_id")
    rows: list[dict[str, Any]] = []
    for summary in artifact.get("callback_summaries", []):
        callback = summary.get("callback")
        for parameter in summary.get("unique_parameters", []):
            source = str(parameter.get("source", ""))
            placement = placement_for_source(source, request_placement=request_placement)
            parts = path_parts(parameter.get("path"))
            if not callback or not placement or not parts:
                continue
            rows.append({
                "plugin": plugin, "entrypoint": entrypoint, "root_callback": callback,
                "source": source, "parameter_path": list(parts), "placement": placement,
                "provenance": {"kind": "opcode_runtime", "request_id": request_id,
                               "observed_count": parameter.get("observed_count", 1),
                               "helper_depth": parameter.get("helper_depth", 0)},
            })
    return rows


def normalize_helper(plugin: str, discovery: dict[str, Any], *, request_placement: str | None = None) -> dict[str, Any] | None:
    source = str(discovery.get("http_source", ""))
    placement = placement_for_source(source, request_placement=request_placement)
    parts = path_parts(discovery.get("parameter_path"))
    entrypoint = discovery.get("entrypoint_name")
    callback = discovery.get("callback_repr") or discovery.get("root_callback")
    if discovery.get("schema_version") != "hookphuzz-runtime-param-v1" or not all((placement, parts, entrypoint, callback)):
        return None
    return {
        "plugin": plugin, "entrypoint": str(entrypoint), "root_callback": str(callback),
        "source": source, "parameter_path": list(parts), "placement": placement,
        "provenance": {"kind": "uopz_helper", "request_id": discovery.get("request_id"),
                       "reader_function": discovery.get("reader_function"),
                       "callback_id": discovery.get("callback_id"),
                       "observation_count": discovery.get("observation_count", 1)},
    }


def merge_evidence(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, tuple[str, ...], str], dict[str, Any]] = {}
    for row in rows:
        key = logical_key(row)
        if key not in grouped:
            grouped[key] = {**row, "parameter_name": path_name(key[4]), "provenance": []}
        provenance = row.get("provenance")
        if isinstance(provenance, dict) and provenance not in grouped[key]["provenance"]:
            grouped[key]["provenance"].append(provenance)
    return [grouped[key] for key in sorted(grouped)]


def phuzz_config(row: dict[str, Any], *, target: str, method: str, fixed: dict[str, str] | None = None) -> dict[str, Any]:
    fixed = fixed or {}
    location = {"body": "body_params", "query": "query_params", "cookie": "cookie_params"}
    config: dict[str, Any] = {"target": target, "methods": [method], "print_timestamps": True,
                              "config_type": "fuzzing_ready", "metadata": {"phase10_provenance": row}}
    sections: dict[str, dict[str, Any]] = {}
    for placement, name in location.items():
        sections[name] = {"data": [], "fixed": [], "fuzz": [], "weight": 1}
        config[name] = sections[name]
    for name, value in fixed.items():
        sections["body_params"]["data"].append({"name": name, "value": value})
        sections["body_params"]["fixed"].append(name)
    section = sections[location[row["placement"]]]
    parameter_name = str(row.get("parameter_name") or path_name(path_parts(row.get("parameter_path")) or ("invalid",)))
    section["data"].append({"name": parameter_name, "value": "PHASE10_MARKER"})
    section["fuzz"].append(parameter_name.replace("[", "\\[").replace("]", "\\]"))
    return config


def gate_summary(gates: dict[str, bool], *, run_id: str, details: dict[str, Any]) -> dict[str, Any]:
    failed = sorted(name for name, passed in gates.items() if not passed)
    return {"schema_version": PHASE10_SCHEMA, "run_id": run_id, "gates": gates,
            "failed_gates": failed, "overall_pass": not failed, **details}
