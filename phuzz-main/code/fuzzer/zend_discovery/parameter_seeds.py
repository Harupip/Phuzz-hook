from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


FORBIDDEN_PARAMETER_NAME = re.compile(
    r"(?:nonce|cookie|secret|password|token|authorization)", re.IGNORECASE
)
SAFE_METHODS = {"GET", "HEAD", "POST"}


def build_parameter_seed(
    endpoint: Mapping[str, Any],
    callback: Mapping[str, Any],
    artifact: Mapping[str, Any],
    extractor: Any,
) -> dict[str, Any]:
    extracted = extractor.extract(dict(callback))
    static_params = extracted.get("input_params", []) if isinstance(extracted, Mapping) else []
    method = _resolve_method(endpoint, artifact, static_params)
    observations = _observed_locations(artifact)
    parameters: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    index: dict[tuple[str, str], dict[str, Any]] = {}

    def add(name: str, location: str, evidence: str, *, fuzzable: bool = True) -> None:
        if not name or name == "action":
            return
        if _blocked_name(name):
            _block(blocked, name, "security_field", evidence)
            return
        if location == "cookie":
            _block(blocked, name, "cookie_field", evidence)
            return
        if location == "body_or_query":
            locations = observations.get(name, set())
            if len(locations) != 1:
                _block(blocked, name, "unresolved_location", evidence)
                return
            location = next(iter(locations))
        if method not in SAFE_METHODS:
            _block(blocked, name, "unsafe_method", evidence)
            return
        if endpoint.get("kind") == "rest" and method in {"GET", "HEAD"} and location != "query":
            _block(blocked, name, "method_location_conflict", evidence)
            return
        key = (name, location)
        existing = index.get(key)
        if existing is None:
            existing = {"name": name, "location": location, "fuzzable": fuzzable, "evidence": [evidence]}
            index[key] = existing
            parameters.append(existing)
        elif evidence not in existing["evidence"]:
            existing["evidence"].append(evidence)

    for item in static_params:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "")
        source = str(item.get("source") or "").upper()
        location = str(item.get("location") or _location_for_source(source))
        if item.get("role") == "security_nonce" or item.get("fuzzable") is False:
            _block(blocked, name, "security_field", f"static:{source or 'unknown'}")
            continue
        add(name, location, f"static:{source or 'unknown'}")

    for name, definition in _argument_definitions(callback).items():
        if _blocked_name(name):
            _block(blocked, name, "security_field", "rest_schema")
        elif method in {"GET", "HEAD"}:
            add(name, "query", "rest_schema")
        else:
            _block(blocked, name, "unresolved_location", "rest_schema")

    for name, locations in observations.items():
        for location in sorted(locations):
            add(name, location, f"runtime:{location}")

    return {
        "callback_id": str(endpoint.get("callback_id") or callback.get("callback_id") or ""),
        "method": method,
        "parameters": parameters,
        "blocked_parameters": blocked,
    }


def _resolve_method(endpoint: Mapping[str, Any], artifact: Mapping[str, Any], static_params: Any) -> str:
    declared = endpoint.get("method")
    if declared:
        return str(declared).upper()
    methods = endpoint.get("methods")
    if isinstance(methods, list) and methods:
        return str(methods[0]).upper()
    observed = artifact.get("http_method")
    if observed:
        return str(observed).upper()
    for item in static_params if isinstance(static_params, list) else []:
        if isinstance(item, Mapping) and str(item.get("source") or "").upper() == "POST":
            return "POST"
    return "GET"


def _argument_definitions(callback: Mapping[str, Any]) -> Mapping[str, Any]:
    definitions = callback.get("argument_definitions", {})
    return definitions if isinstance(definitions, Mapping) else {}


def _observed_locations(artifact: Mapping[str, Any]) -> dict[str, set[str]]:
    request_params = artifact.get("request_params", {})
    if not isinstance(request_params, Mapping):
        return {}
    observations: dict[str, set[str]] = {}
    for key, location in (("query_params", "query"), ("body_params", "body")):
        values = request_params.get(key, {})
        if isinstance(values, Mapping):
            for name in values:
                observations.setdefault(str(name), set()).add(location)
    cookies = request_params.get("cookies", [])
    if isinstance(cookies, Mapping):
        cookies = cookies.keys()
    if isinstance(cookies, list) or hasattr(cookies, "__iter__"):
        for name in cookies:
            observations.setdefault(str(name), set()).add("cookie")
    return observations


def _location_for_source(source: str) -> str:
    return {"GET": "query", "POST": "body", "REQUEST": "body_or_query", "COOKIE": "cookie"}.get(source, "body_or_query")


def _blocked_name(name: str) -> bool:
    return bool(FORBIDDEN_PARAMETER_NAME.search(name))


def _block(blocked: list[dict[str, Any]], name: str, reason: str, evidence: str) -> None:
    if not name or any(row["name"] == name for row in blocked):
        return
    blocked.append({"name": name, "reason": reason, "evidence": [evidence]})
