"""Deterministic Phase 12 REST argument normalization and initial seeds."""
from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Mapping

SCHEMA_VERSION = 1
_NAMED = re.compile(r"\(\?P<([A-Za-z_][A-Za-z0-9_]*)>")
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_FIELDS = ("type", "required", "default", "enum", "description", "format", "minimum", "maximum", "minLength", "maxLength", "pattern", "items", "properties")


def methods(value: Any) -> list[str]:
    result: list[str] = []
    def add(item: Any) -> None:
        if isinstance(item, (list, tuple)):
            for child in item: add(child)
            return
        for part in str(item or "").replace("|", ",").split(","):
            method = part.strip().upper()
            if method and method in _METHODS and method not in result: result.append(method)
    add(value)
    return result


def callback(value: Any) -> str | None:
    if value is None: return None
    if isinstance(value, str): return value
    if isinstance(value, (list, tuple)) and len(value) == 2:
        left = value[0] if isinstance(value[0], str) else value[0].__class__.__name__
        return f"{left}::{value[1]}"
    return "unsupported_callable"


def initial_value(schema: Mapping[str, Any]) -> dict[str, Any]:
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return {"seed_status": "supported", "seed": deepcopy(enum[0]), "additional_seeds": deepcopy(enum[1:]), "rule": "first_enum"}
    kind = schema.get("type")
    pattern = schema.get("pattern")
    if pattern:
        pattern_values = {r"\d+": "1", "[0-9]+": "1", "[a-z]+": "test"}
        if pattern not in pattern_values: return {"seed_status": "unsupported", "seed": None, "additional_seeds": [], "rule": "unsupported_pattern", "reason": str(pattern)}
        return {"seed_status": "supported", "seed": pattern_values[pattern], "additional_seeds": [], "rule": "pattern_subset"}
    if kind == "string": value = "HOOKPHUZZ_PHASE12"
    elif kind == "integer": value = max(1, int(schema.get("minimum", 1)))
    elif kind == "number": value = max(1.0, float(schema.get("minimum", 1.0)))
    elif kind == "boolean": value = True
    elif kind == "array" and isinstance(schema.get("items"), Mapping):
        child = initial_value(schema["items"])
        if child["seed_status"] != "supported": return child
        value = [child["seed"]]
    elif kind == "object" and isinstance(schema.get("properties"), Mapping) and schema["properties"]:
        value = {}
        for name, child_schema in sorted(schema["properties"].items()):
            child = initial_value(child_schema if isinstance(child_schema, Mapping) else {})
            if child["seed_status"] != "supported": return {"seed_status": "unsupported", "seed": None, "additional_seeds": [], "rule": "unsupported_object_property", "reason": str(name)}
            value[name] = child["seed"]
    elif kind == "object": return {"seed_status": "unsupported", "seed": None, "additional_seeds": [], "rule": "open_object"}
    else: return {"seed_status": "unsupported", "seed": None, "additional_seeds": [], "rule": "unknown_type"}
    additional = [deepcopy(value)] if "default" in schema and schema["default"] != value else []
    return {"seed_status": "supported", "seed": schema.get("default", value), "additional_seeds": additional, "rule": "default" if "default" in schema else f"{kind}_baseline"}


def normalize_route(capture: Mapping[str, Any]) -> list[dict[str, Any]]:
    route = str(capture.get("route") or capture.get("route_pattern") or "")
    path_names = set(_NAMED.findall(route))
    declared = capture.get("argument_definitions")
    if not isinstance(declared, Mapping): declared = {}
    route_methods = methods(capture.get("methods")) or ["UNSUPPORTED"]
    rows: list[dict[str, Any]] = []
    for method in route_methods:
        for name, definition in sorted(declared.items()):
            if not isinstance(definition, Mapping):
                record = _record(capture, route, method, str(name), {}, path_names)
                record["parameter"]["parameter_status"] = "unsupported"
                record["parameter"]["export_allowed"] = False
            else:
                record = _record(capture, route, method, str(name), definition, path_names)
            rows.append(record)
    return rows


def _record(capture: Mapping[str, Any], route: str, method: str, name: str, source: Mapping[str, Any], path_names: set[str]) -> dict[str, Any]:
    location = "path" if name in path_names else "unknown"
    parameter = {"name": name, "location": location, "location_candidates": [] if location == "path" else ["query", "json", "form"], "location_confidence": "route_pattern_exact" if location == "path" else "schema_only", "type": source.get("type", "unknown"), "required": source.get("required", False), "default_present": "default" in source, "default": deepcopy(source.get("default")), "enum": deepcopy(source.get("enum", [])) if isinstance(source.get("enum", []), list) else [], "description": source.get("description"), "format": source.get("format"), "minimum": source.get("minimum"), "maximum": source.get("maximum"), "min_length": source.get("minLength"), "max_length": source.get("maxLength"), "pattern": source.get("pattern"), "items": deepcopy(source.get("items")), "properties": deepcopy(source.get("properties")), "validate_callback": callback(source.get("validate_callback")), "sanitize_callback": callback(source.get("sanitize_callback")), "schema_source": "route_declared", "schema_confidence": "exact", "runtime_observed": False, "runtime_readers": [], "value_origin": None, "raw_value": None, "observed_value": None, "transformed": None, "seed_status": None, "seed": None, "additional_seeds": [], "parameter_status": "declared_not_observed", "export_allowed": False, "evidence": [{"source": "route_declared", "field": key, "value": deepcopy(source[key]), "confidence": "exact"} for key in _FIELDS if key in source]}
    generated = initial_value(source)
    parameter.update(generated)
    return {"schema_version": SCHEMA_VERSION, "entrypoint_id": str(capture.get("callback_id") or capture.get("callback") or ""), "namespace": capture.get("namespace"), "route_pattern": route, "endpoint_definition_index": capture.get("endpoint_definition_index", 0), "method": method, "parameter": parameter}
