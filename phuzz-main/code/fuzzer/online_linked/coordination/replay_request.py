"""Restore replay inputs from a correlated request."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from filesystem_paths import filesystem_path
from online_linked.coordination.errors import OnlineLinkedError


def restore_request_values(
    config: dict[str, Any], evidence: Mapping[str, Any], parent: Mapping[str, Any],
    *, only_parameters: set[tuple[str, str, str]] | None = None,
) -> None:
    """Seed child inputs from this correlated request, retaining fuzz selectors."""
    request = evidence.get("request") or {}
    if not isinstance(request, Mapping):
        raise OnlineLinkedError("UNSUPPORTED_REQUEST: expected an object")
    params = request.get("request_params")
    if params is None:
        params = {}
    if not isinstance(params, Mapping):
        raise OnlineLinkedError("UNSUPPORTED_REQUEST_PARAMS: expected an object")
    parent_config = json.loads(filesystem_path(Path(str(parent["config_path"]))).read_text(encoding="utf-8-sig"))
    headers = config.get("headers", {}).get("data", [])
    is_json = any(
        str(row.get("name", "")).lower() == "content-type"
        and "json" in str(row.get("value", "")).lower() for row in headers
    )
    values = []
    section_identity = {
        "query_params": ("GET", "query"),
        "body_params": ("POST", "form"),
        "headers": ("HEADER", "header"),
        "cookies": ("COOKIE", "cookie"),
    }
    for section_name in ("query_params", "body_params", "headers", "cookies"):
        section = config.get(section_name)
        if not isinstance(section, dict):
            continue
        bucket = "json_params" if section_name == "body_params" and is_json else section_name
        observed, source_status, source_reason = _request_bucket_values(params, bucket)
        parent_section = parent_config.get(section_name, {})
        if not isinstance(parent_section, Mapping):
            parent_section = {}
        fixed = parent_section.get("fixed", [])
        if not isinstance(fixed, list):
            raise OnlineLinkedError(f"UNSUPPORTED_CONFIG_BUCKET: {section_name}.fixed must be a list")
        for row in section.get("data", []):
            name = str(row["name"])
            transport, location = section_identity[section_name]
            if only_parameters is not None and (name, transport, location) not in only_parameters:
                continue
            value = observed
            path = [name] if name in observed else [part for part in re.split(r"\[|\]", name) if part]
            found = True
            for part in path:
                if isinstance(value, Mapping) and part in value:
                    value = value[part]
                elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
                    value = value[int(part)]
                else:
                    found = False
                    break
            if found:
                row["value"] = copy.deepcopy(value)
                row.pop("seeds", None)
            if any(re.match(selector, name) for selector in fixed):
                selector = re.escape(name)
                if selector not in section.setdefault("fixed", []):
                    section["fixed"].append(selector)
                section["fuzz"] = [item for item in section.get("fuzz", []) if item != selector]
            value_record = {
                "name": name,
                "bucket": bucket,
                "request_id": evidence.get("request_id"),
                "run_id": evidence.get("worker_run_id") or evidence.get("run_id") or parent["worker_run_id"],
                "value_origin": "observed" if found else ("probe" if source_status == "observed" else source_status),
            }
            if not found:
                value_record["reason"] = source_reason or "REQUEST_VALUE_MISSING"
            values.append(value_record)
    metadata = config.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise OnlineLinkedError("PROBE_CONFIG_METADATA_INVALID")
    previous = metadata.get("online_request_seed")
    previous_values = previous.get("values", []) if isinstance(previous, Mapping) else []
    records: dict[tuple[str, str], dict[str, Any]] = {}
    for value in previous_values if isinstance(previous_values, list) else []:
        if isinstance(value, Mapping):
            records[(str(value.get("bucket") or ""), str(value.get("name") or ""))] = dict(value)
    for value in values:
        records[(str(value.get("bucket") or ""), str(value.get("name") or ""))] = value
    request_ids = []
    if isinstance(previous, Mapping):
        request_ids.extend(str(item) for item in previous.get("evidence_request_ids", []) if str(item))
        if previous.get("request_id") and previous.get("request_id") != "multiple":
            request_ids.append(str(previous["request_id"]))
    request_id = str(evidence.get("request_id") or "")
    if request_id:
        request_ids.append(request_id)
    request_ids = list(dict.fromkeys(request_ids))
    metadata["online_request_seed"] = {
        "request_id": request_ids[0] if len(request_ids) == 1 else "multiple",
        "run_id": parent["worker_run_id"],
        "evidence_request_ids": request_ids,
        "values": list(records.values()),
    }

def _request_bucket_values(
    params: Mapping[str, Any], bucket: str,
) -> tuple[Mapping[str, Any], str, str]:
    """Decode producer buckets without treating names or falsey values as data loss."""
    if bucket == "json_params":
        if "json_params" not in params:
            status = str(params.get("json_params_status") or "").strip().lower()
            if status in {"invalid", "error"}:
                return {}, status, str(params.get("json_params_error") or f"JSON_PARAMS_{status.upper()}")
            return {}, "missing", "JSON_PARAMS_MISSING"
        status = str(params.get("json_params_status") or "decoded").strip().lower()
        if status in {"missing", "invalid", "error", "not_json"}:
            return {}, status, str(params.get("json_params_error") or f"JSON_PARAMS_{status.upper()}")
        observed = params.get("json_params")
        if isinstance(observed, Mapping):
            return observed, "empty" if not observed else "observed", ""
        json_type = str(params.get("json_params_type") or "").strip().lower()
        if not json_type:
            if isinstance(observed, list):
                json_type = "array"
            elif observed is None:
                json_type = "null"
            elif isinstance(observed, bool):
                json_type = "boolean"
            elif isinstance(observed, (int, float)):
                json_type = "number"
            elif isinstance(observed, str):
                json_type = "string"
            else:
                json_type = type(observed).__name__
        raise OnlineLinkedError(
            f"UNSUPPORTED_REQUEST_BUCKET: json_params must be an object (got {json_type})"
        )

    if bucket not in params:
        return {}, "missing", "REQUEST_BUCKET_MISSING"
    observed = params[bucket]
    if bucket in {"query_params", "body_params"} and observed == []:
        return {}, "empty", ""
    if bucket == "cookies" and isinstance(observed, list):
        if not all(isinstance(name, str) for name in observed):
            raise OnlineLinkedError("UNSUPPORTED_REQUEST_BUCKET: cookies must be a list of names")
        return {}, "names_only", "COOKIE_VALUES_NOT_EXPORTED"
    if not isinstance(observed, Mapping):
        raise OnlineLinkedError(f"UNSUPPORTED_REQUEST_BUCKET: {bucket} must be an object")
    return observed, "observed", ""
