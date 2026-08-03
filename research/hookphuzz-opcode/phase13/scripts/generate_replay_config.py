#!/usr/bin/env python3
"""Generate fail-closed replay configs from a catalog and optional auth overlay."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from classify_authentication import ValidationError, atomic, validate

VALID_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}


def _fail(code: str) -> None:
    raise ValueError(code)


def _validate_parameters(record: dict[str, Any], plugin: str, version: str) -> None:
    for field, origin in (("schema_parameters", "schema"), ("runtime_parameters", "runtime")):
        parameters = record.get(field, [])
        if not isinstance(parameters, list):
            _fail("unsupported_parameter")
        for parameter in parameters:
            if not isinstance(parameter, dict) or not isinstance(parameter.get("name"), str) or not parameter["name"]:
                _fail("unsupported_parameter")
            if parameter.get("parameter_origin", parameter.get("origin")) != origin:
                _fail("unsupported_parameter")
            if parameter.get("unsupported_value_markers"):
                _fail("unsupported_parameter")
            if field == "runtime_parameters" and (parameter.get("plugin_slug", plugin) != plugin or parameter.get("plugin_version", version) != version):
                _fail("cross_plugin_runtime_parameter_evidence")


def _catalog_record(catalog: Path, catalog_run: str, catalog_sha: str, plugin: str, version: str, endpoint: str) -> tuple[dict[str, Any], str]:
    if not catalog.is_file():
        _fail("missing_catalog")
    raw = catalog.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != catalog_sha:
        _fail("catalog_sha_mismatch")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        _fail("malformed_catalog")
    records = parsed.get("records") if isinstance(parsed, dict) else None
    if not isinstance(records, list):
        _fail("malformed_catalog")
    record = next((item for item in records if isinstance(item, dict) and item.get("endpoint_identity") == endpoint), None)
    if record is None:
        _fail("missing_endpoint_identity")
    for key, expected, failure in (("run_id", catalog_run, "stale_catalog_run"), ("plugin_slug", plugin, "plugin_mismatch"), ("plugin_version", version, "version_mismatch")):
        if record.get(key) != expected:
            _fail(failure)
    _validate_parameters(record, plugin, version)
    return record, sha


def _runtime_parameters(path: Path | None, *, replay_run: str, request_id: str, plugin: str, version: str, endpoint: str, route: str, method: str, callback: str) -> set[str]:
    if path is None or not path.is_file():
        _fail("missing_runtime_parameter_evidence")
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        _fail("malformed_runtime_parameter_evidence")
    expected = {"replay_run_id": replay_run, "request_id": request_id, "plugin_slug": plugin, "plugin_version": version, "endpoint_id": endpoint, "route": route, "method": method, "callback": callback}
    if not isinstance(evidence, dict) or any(evidence.get(key) != value for key, value in expected.items()):
        _fail("runtime_parameter_evidence_mismatch")
    parameters = evidence.get("parameters")
    if not isinstance(parameters, list):
        _fail("malformed_runtime_parameter_evidence")
    names = {item.get("name") for item in parameters if isinstance(item, dict) and item.get("runtime_source") == "WP_REST_Request::get_param" and item.get("redacted_value_metadata") == "not_persisted"}
    if not names or any(not isinstance(name, str) or not name for name in names):
        _fail("unsupported_parameter")
    return names


def generate(catalog: Path, *, catalog_run: str, catalog_sha: str, plugin: str, version: str, endpoint: str, replay_type: str, replay_run: str, request_id: str, output: Path, route_id: str | None = None, overlay: Path | None = None, query_parameters: dict[str, str] | None = None, runtime_parameter_evidence: Path | None = None) -> dict[str, Any]:
    if replay_type not in {"public", "authenticated"}:
        _fail("unsupported_authentication")
    record, sha = _catalog_record(catalog, catalog_run, catalog_sha, plugin, version, endpoint)
    methods = record.get("methods")
    if not isinstance(methods, list) or len(methods) != 1 or not isinstance(methods[0], str) or methods[0] not in VALID_METHODS:
        _fail("unresolved_method")
    if record.get("method_origin") != "runtime_registry" or record.get("ownership") != "plugin":
        _fail("unsupported_endpoint")
    route = record.get("route")
    if not isinstance(route, str) or not route.startswith("/"):
        _fail("unresolved_route")
    target = "http://localhost/wp-json" + route
    if route_id:
        target = target.replace("(?P<id>\\d+)", route_id)
    if "(?P<" in target:
        _fail("unresolved_route_parameter")
    metadata = {
        "source_catalog_path": str(catalog), "source_catalog_sha256": sha, "source_catalog_run_id": catalog_run,
        "plugin": plugin, "plugin_version": version, "endpoint_identity": endpoint, "route": route,
        "method": methods[0], "callback": record.get("callback"), "permission_callback": record.get("permission_callback"),
        "ownership_evidence": record.get("ownership_evidence", []), "schema_parameters": record.get("schema_parameters", []),
        "runtime_parameters": record.get("runtime_parameters", []), "catalog_authentication": record.get("authentication"),
        "effective_authentication": replay_type, "authentication_origin": "catalog" if replay_type == "public" else "current_runtime_permission_probe",
        "limitations": record.get("limitations", []), "replay_run_id": replay_run, "request_id": request_id,
    }
    if replay_type == "public":
        if record.get("authentication") != "public" or overlay is not None or query_parameters or runtime_parameter_evidence is not None:
            _fail("unsupported_authentication")
    else:
        if overlay is None or not overlay.is_file():
            _fail("missing_authentication_overlay")
        try:
            evidence = validate(json.loads(overlay.read_text(encoding="utf-8")), replay_run=replay_run, catalog_run=catalog_run, catalog_sha=sha, plugin=plugin, version=version, endpoint=endpoint, route=route, method=methods[0])
        except json.JSONDecodeError:
            _fail("malformed_overlay")
        except ValidationError as error:
            _fail(str(error))
        if evidence["classification"] != "authenticated":
            _fail("unsupported_authentication")
        metadata["authentication_reference"] = {
            "path": str(overlay), "sha256": hashlib.sha256(overlay.read_bytes()).hexdigest(),
            "classification": "authenticated", "redacted_presence_flags": {"cookie_present": False, "nonce_present": False, "authorization_present": False},
        }
        if query_parameters:
            observed = _runtime_parameters(runtime_parameter_evidence, replay_run=replay_run, request_id=request_id, plugin=plugin, version=version, endpoint=endpoint, route=route, method=methods[0], callback=record.get("callback"))
            if set(query_parameters) - observed:
                _fail("unsupported_parameter")
    if output.exists():
        _fail("output_collision")
    config = {"target": target, "methods": [methods[0]], "print_timestamps": False, "metadata": metadata}
    if query_parameters:
        config["query_params"] = {"data": [{"name": name, "value": value} for name, value in sorted(query_parameters.items())], "fixed": ["^" + re.escape(name) + "$" for name in sorted(query_parameters)]}
    atomic(output, config)
    atomic(output.with_name(output.stem + "-generation.json"), {"passed": True, "failure_classification": None, "config_sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "endpoint_identity": endpoint, "replay_run_id": replay_run})
    return config


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, required=True); parser.add_argument("--catalog-run", required=True)
    parser.add_argument("--catalog-sha", required=True); parser.add_argument("--plugin", required=True)
    parser.add_argument("--version", required=True); parser.add_argument("--endpoint", required=True)
    parser.add_argument("--type", choices=["public", "authenticated"], required=True); parser.add_argument("--replay-run", required=True)
    parser.add_argument("--request-id", required=True); parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--route-id"); parser.add_argument("--authentication-evidence", type=Path); parser.add_argument("--runtime-parameter-evidence", type=Path); parser.add_argument("--query-parameter", action="append", default=[])
    args = parser.parse_args()
    try:
        parameters = {}
        for item in args.query_parameter:
            if "=" not in item: _fail("unsupported_parameter")
            name, value = item.split("=", 1)
            if not name or name in parameters: _fail("unsupported_parameter")
            parameters[name] = value
        generate(args.catalog, catalog_run=args.catalog_run, catalog_sha=args.catalog_sha, plugin=args.plugin, version=args.version, endpoint=args.endpoint, replay_type=args.type, replay_run=args.replay_run, request_id=args.request_id, output=args.output, route_id=args.route_id, overlay=args.authentication_evidence, query_parameters=parameters or None, runtime_parameter_evidence=args.runtime_parameter_evidence)
    except ValueError as error:
        print(error)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
