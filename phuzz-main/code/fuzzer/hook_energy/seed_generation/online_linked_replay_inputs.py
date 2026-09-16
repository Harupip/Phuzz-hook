"""Choose bounded, evidence-backed replay-input adjustments."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from fuzz_guidance.cmplog.hints import normalize_comparison_events


_REQUEST_SOURCE = "REQUEST"
_LOCATION_BUCKETS = {
    "query": "query_params",
    "form": "body_params",
    "json": "json_params",
    "cookie": "cookies",
}
_REQUEST_SOURCE_BY_LOCATION = {
    "query": "GET",
    "form": "POST",
    "json": "REST_JSON",
    "cookie": "COOKIE",
}


def propose_replay_inputs(
    request_params: Mapping[str, Any],
    zend_artifact: Mapping[str, Any],
    *,
    parameter_transports: Sequence[Mapping[str, Any]],
    expected_request_id: str,
    expected_run_id: str,
    expected_callback: str,
) -> list[dict[str, Any]]:
    """Return one-field CMPLOG adjustments for one correlated trial.

    This helper only transforms an already verified request context. It does
    not read files, run a sender, or admit a parameter.
    """

    request_id = str(expected_request_id or "").strip()
    run_id = str(expected_run_id or "").strip()
    callback = _canonical_callback(expected_callback)
    if not request_id or not run_id or not callback:
        return []
    if not isinstance(request_params, Mapping) or not isinstance(zend_artifact, Mapping):
        return []
    if str(zend_artifact.get("request_id") or "").strip() != request_id:
        return []
    artifact_run_id = str(
        zend_artifact.get("run_id") or zend_artifact.get("legacy_run_id") or ""
    ).strip()
    if artifact_run_id != run_id:
        return []

    transports = _normalize_transports(parameter_transports)
    if not transports:
        return []
    fuzz_params = _fuzz_parameters(request_params, transports)
    if not fuzz_params:
        return []

    proposals: list[dict[str, Any]] = []
    seen_inputs: set[str] = set()
    events = zend_artifact.get("comparison_events")
    if not isinstance(events, list):
        return []
    for event in events:
        if not isinstance(event, Mapping) or not _event_is_correlated(event, request_id, run_id, callback):
            continue
        parameter = _event_parameter_name(event)
        if not parameter:
            continue
        matches = [
            row for row in transports
            if row["name"] == parameter and _event_matches_transport(event, row)
        ]
        if len(matches) != 1:
            continue
        if str(event.get("source") or "").strip().upper() == _REQUEST_SOURCE:
            actual_buckets = [
                bucket for bucket in _LOCATION_BUCKETS.values()
                if isinstance(request_params.get(bucket), Mapping)
                and parameter in request_params[bucket]
            ]
            if len(actual_buckets) != 1 or actual_buckets[0] != _request_bucket(matches[0]):
                continue
        transport = matches[0]
        normalized_source = _normalized_hint_source(event, transport)
        normalized_event = dict(event)
        normalized_event["source"] = normalized_source
        normalized_artifact = {
            "request_id": request_id,
            "comparison_events": [normalized_event],
        }
        hints = normalize_comparison_events(normalized_artifact, fuzz_params)
        if len(hints) != 1:
            continue
        hint = hints[0]
        bucket = _request_bucket(transport)
        current_bucket = request_params.get(bucket)
        if not isinstance(current_bucket, Mapping) or parameter not in current_bucket:
            continue
        updated = copy.deepcopy(dict(request_params))
        updated_bucket = updated.get(bucket)
        if not isinstance(updated_bucket, dict):
            continue
        updated_bucket[parameter] = copy.deepcopy(hint["candidate_value"])
        input_key = _input_key(updated)
        if input_key in seen_inputs:
            continue
        seen_inputs.add(input_key)
        provenance = {
            "request_id": request_id,
            "run_id": run_id,
            "callback": callback,
            "parameter": parameter,
            "source": str(event.get("source") or "").upper(),
            "transport_source": transport["source"],
            "location": transport["location"],
            "path": copy.deepcopy(hint.get("path") or []),
            "opcode": hint.get("opcode"),
            "observed_value": copy.deepcopy(hint.get("observed_value")),
            "candidate_value": copy.deepcopy(hint.get("candidate_value")),
            "reason": "cmplog",
            "mutation_source": "cmplog",
        }
        proposals.append({"request_params": updated, "hint_provenance": provenance})
    return proposals


def _canonical_callback(value: Any) -> str:
    return re.sub(r"\s*(?:->|::)\s*", "::", str(value or "").strip())


def _event_is_correlated(
    event: Mapping[str, Any], request_id: str, run_id: str, callback: str,
) -> bool:
    event_request_id = event.get("request_id")
    if event_request_id is not None and str(event_request_id).strip() != request_id:
        return False
    event_run_id = event.get("run_id") or event.get("legacy_run_id")
    if event_run_id is not None and str(event_run_id).strip() != run_id:
        return False
    event_callback = event.get("callback") or event.get("callback_repr")
    return _canonical_callback(event_callback) == callback


def _event_parameter_name(event: Mapping[str, Any]) -> str:
    path = event.get("path")
    if not isinstance(path, (list, tuple)) or not path:
        return ""
    parts = list(path)
    if parts and parts[0] in {"GET", "POST", "JSON"}:
        parts = parts[1:]
    if not parts or not all(isinstance(part, str) and part for part in parts):
        return ""
    return str(parts[0]) + "".join(f"[{part}]" for part in parts[1:])


def _normalize_transports(value: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if isinstance(value, Mapping):
        for key, raw in value.items():
            row: dict[str, Any] = {"name": str(key)}
            if isinstance(raw, Mapping):
                row.update(raw)
            elif isinstance(raw, (list, tuple)):
                if len(raw) > 0:
                    row["source"] = raw[0]
                if len(raw) > 1:
                    row["location"] = raw[1]
            else:
                row["source"] = raw
            rows.append(row)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for raw in value:
            if isinstance(raw, Mapping):
                rows.append(dict(raw))
            elif isinstance(raw, (list, tuple)) and len(raw) >= 3:
                rows.append({"name": raw[0], "source": raw[1], "location": raw[2]})

    normalized: list[dict[str, Any]] = []
    for row in rows:
        name = str(row.get("name") or "").strip()
        source = str(row.get("source") or row.get("transport") or "").strip().upper()
        location = str(row.get("location") or row.get("placement") or "").strip().lower()
        if not name or not source or location not in _LOCATION_BUCKETS:
            continue
        if row.get("adjustable") is False or row.get("fixed") is True or row.get("fuzzable") is False:
            continue
        normalized.append({"name": name, "source": source, "location": location})
    return normalized


def _request_bucket(transport: Mapping[str, Any]) -> str:
    return _LOCATION_BUCKETS[str(transport["location"])]


def _fuzz_parameters(
    request_params: Mapping[str, Any], transports: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    fuzz_params: dict[str, dict[str, Any]] = {
        "query_params": {}, "body_params": {}, "cookies": {},
    }
    for transport in transports:
        bucket = _request_bucket(transport)
        values = request_params.get(bucket)
        if isinstance(values, Mapping) and transport["name"] in values:
            placement = "body_params" if bucket == "json_params" else bucket
            fuzz_params[placement][transport["name"]] = values[transport["name"]]
    return fuzz_params


def _event_matches_transport(event: Mapping[str, Any], transport: Mapping[str, Any]) -> bool:
    source = str(event.get("source") or "").strip().upper()
    if source == _REQUEST_SOURCE:
        return True
    if source == "REST":
        path = event.get("path")
        if not isinstance(path, (list, tuple)) or not path:
            return False
        path_source = str(path[0]).upper()
        aliases = {
            "REST_GET": {"GET", "QUERY"},
            "REST_POST": {"POST", "FORM"},
            "REST_JSON": {"JSON"},
        }
        return path_source in aliases.get(transport["source"], {transport["source"]})
    expected = transport["source"]
    if expected == "JSON":
        expected = "REST_JSON"
    return source == expected


def _normalized_hint_source(event: Mapping[str, Any], transport: Mapping[str, Any]) -> str:
    source = str(event.get("source") or "").strip().upper()
    if source == _REQUEST_SOURCE:
        return _REQUEST_SOURCE_BY_LOCATION[transport["location"]]
    if source == "JSON":
        return "REST_JSON"
    return source


def _input_key(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
