#!/usr/bin/env python3
"""Validate and atomically classify redacted, current-run permission evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
CLASSIFICATIONS = {"public", "authenticated", "conditional", "unresolved"}
RAW_SECRET_VALUE = re.compile(r"(?i)(?:cookie|authorization|x-wp-nonce|nonce|password|session[_-]?token)\s*[:=]|\bbearer\s+\S+")
REQUIRED = (
    "schema_version", "permission_probe_run_id", "replay_run_id", "catalog_run_id",
    "catalog_sha256", "plugin_slug", "plugin_version", "endpoint_id", "route", "method",
    "callback", "permission_callback", "classification", "classification_origin",
    "anonymous_control", "invalidated_auth_control", "valid_auth_control",
    "permission_callback_reached", "endpoint_callback_reached", "request_ids",
    "source_artifacts", "source_artifact_sha256", "redaction_pass", "containment_pass",
    "limitations",
)


class ValidationError(ValueError):
    """A stable, machine-readable evidence rejection."""


def atomic(path: Path, value: dict[str, Any]) -> None:
    """Write JSON via a same-directory temporary file then replace it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _fail(code: str) -> None:
    raise ValidationError(code)


def _secret_free(value: Any, path: str = "") -> None:
    """Permit redacted presence booleans, never secret-bearing fields."""
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            safe_flag = lowered.endswith("_present") or lowered.endswith("_redacted")
            sensitive = any(word in lowered for word in ("cookie", "authorization", "password", "session_token", "session-token", "nonce"))
            if sensitive and (not safe_flag or not isinstance(child, bool)):
                _fail("raw_authentication_material")
            if sensitive:
                continue
            _secret_free(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _secret_free(child, f"{path}[{index}]")
    elif isinstance(value, str) and RAW_SECRET_VALUE.search(value):
        _fail("raw_authentication_material")


def _nonempty_string(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(code)
    return value


def _control(value: Any, name: str, *, denied: bool) -> str:
    if not isinstance(value, dict):
        _fail(f"missing_{name}_control")
    request_id = _nonempty_string(value.get("request_id"), "request_id_mismatch")
    expected = "denied" if denied else "accepted"
    if value.get(expected) is not True:
        _fail(f"missing_{name}_{expected}")
    if not denied and value.get("current_run") is not True:
        _fail("stale_replay_evidence")
    return request_id


def validate(value: Any, *, replay_run: str | None = None, catalog_run: str | None = None, catalog_sha: str | None = None, plugin: str | None = None, version: str | None = None, endpoint: str | None = None, route: str | None = None, method: str | None = None) -> dict[str, Any]:
    """Validate the schema and authenticated proof; return only valid evidence."""
    if not isinstance(value, dict):
        _fail("malformed_overlay")
    for key in REQUIRED:
        if key not in value:
            _fail(f"missing_{key}")
    if value["schema_version"] != SCHEMA_VERSION:
        _fail("wrong_schema_version")
    if value["classification"] not in CLASSIFICATIONS:
        _fail("invalid_classification")
    for key in ("permission_probe_run_id", "replay_run_id", "catalog_run_id", "catalog_sha256", "plugin_slug", "plugin_version", "endpoint_id", "route", "method", "callback", "permission_callback", "classification_origin"):
        _nonempty_string(value[key], f"missing_{key}")
    if replay_run is not None and value["replay_run_id"] != replay_run:
        _fail("stale_replay_evidence")
    for field, expected, failure in (("catalog_run_id", catalog_run, "stale_catalog_run"), ("catalog_sha256", catalog_sha, "catalog_sha_mismatch"), ("plugin_slug", plugin, "plugin_mismatch"), ("plugin_version", version, "version_mismatch"), ("endpoint_id", endpoint, "endpoint_mismatch"), ("route", route, "route_mismatch"), ("method", method, "method_mismatch")):
        if expected is not None and value[field] != expected:
            _fail(failure)
    _secret_free(value)
    if not isinstance(value["source_artifacts"], list) or not isinstance(value["source_artifact_sha256"], dict) or not isinstance(value["limitations"], list):
        _fail("malformed_evidence_artifacts")
    for name in ("anonymous", "invalidated_auth", "valid_auth"):
        control = value[f"{name}_control"]
        if not isinstance(control, dict):
            _fail(f"missing_{name}_control")
        _nonempty_string(control.get("request_id"), "request_id_mismatch")
    if value["classification"] != "authenticated":
        return value

    anonymous = _control(value["anonymous_control"], "anonymous", denied=True)
    invalidated = _control(value["invalidated_auth_control"], "invalidated_auth", denied=True)
    valid = _control(value["valid_auth_control"], "valid_auth", denied=False)
    if value["permission_callback_reached"] is not True:
        _fail("permission_callback_not_reached")
    if value["endpoint_callback_reached"] is not True:
        _fail("endpoint_callback_not_reached")
    ids = value["request_ids"]
    if not isinstance(ids, dict) or any(ids.get(key) != expected for key, expected in {
        "anonymous": anonymous, "invalidated_auth": invalidated, "valid_auth": valid,
        "permission_callback": valid, "endpoint_callback": valid,
    }.items()):
        _fail("request_id_mismatch")
    if value["redaction_pass"] is not True:
        _fail("redaction_failed")
    if value["containment_pass"] is not True:
        _fail("containment_failed")
    return value


def result_for(value: Any, **expected: str | None) -> dict[str, Any]:
    gates = {"schema": False, "secrets": False, "controls": False, "callbacks": False, "correlation": False, "redaction": False, "containment": False}
    try:
        validated = validate(value, **expected)
        gates = {key: True for key in gates}
        return {"passed": True, "failure_classification": None, "validation_gates": gates, "classification": validated["classification"]}
    except ValidationError as error:
        return {"passed": False, "failure_classification": str(error), "validation_gates": gates}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--replay-run"); parser.add_argument("--catalog-run"); parser.add_argument("--catalog-sha")
    parser.add_argument("--plugin"); parser.add_argument("--version"); parser.add_argument("--endpoint")
    parser.add_argument("--route"); parser.add_argument("--method")
    args = parser.parse_args()
    try:
        value = json.loads(args.input.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        value = None
    result = result_for(value, replay_run=args.replay_run, catalog_run=args.catalog_run, catalog_sha=args.catalog_sha, plugin=args.plugin, version=args.version, endpoint=args.endpoint, route=args.route, method=args.method)
    result["input_sha256"] = hashlib.sha256(args.input.read_bytes()).hexdigest() if args.input.is_file() else None
    atomic(args.output.with_name(args.output.stem + "-result.json"), result)
    if not result["passed"]:
        return 2
    value["classification_origin"] = "current_runtime_permission_probe"
    atomic(args.output, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
